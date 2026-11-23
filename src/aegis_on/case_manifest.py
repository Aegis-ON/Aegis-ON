from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from .case_intake_inventory import INTAKE, verified_paths
from .codebert_data import read_jsonl

CaseId = Annotated[str, StringConstraints(pattern=r"^CASE-[A-Z0-9-]+$")]
Text = Annotated[str, StringConstraints(min_length=1, strip_whitespace=True)]
Label = Literal[
    "normal_approved", "normal_authorized_runtime", "operational_anomaly", "policy_blocked",
    "needs_investigation", "confirmed_security_incident", "synthetic_training_only",
]
COMMON_FIELDS: Final = frozenset({
    "case_id", "data_origin", "label", "synthetic", "eligible_for_training", "case_group",
})


class ManifestIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, hide_input_in_errors=True)

    case_id: CaseId
    data_origin: Literal["actual_observed", "synthetic"]
    label: Label
    synthetic: bool
    eligible_for_training: Literal["yes", "no", "synthetic_only"]
    case_group: Text


class LabelEntry(ManifestIdentity):
    display_label: Text
    label_status: Literal["provisional", "synthetic_approved", "pending_security_review"]
    label_source: Text
    confidence: Literal["high", "medium", "low"]
    not_actual_incident: bool
    eligible_for_production_validation: bool
    eligible_for_security_incident_statistics: bool
    evidence_paths: tuple[Text, ...] = Field(min_length=1)


class SplitEntry(ManifestIdentity):
    split: Literal["train", "validation", "test", "not_assigned", "synthetic_demo"]
    split_status: Literal["assigned", "insufficient_for_supervised_model_evaluation", "synthetic_demo_only"]
    leakage_key: CaseId
    inclusion_decision: Text
    rationale: Text


class AuthoritativeInputs(BaseModel):
    label_manifest: Literal["label_manifest.jsonl"]
    split_manifest: Literal["training_split_manifest.jsonl"]
    labeling_guideline: Literal["labeling_guideline.md"]
    actual_cases_root: Literal["runtime_cases"]
    synthetic_cases_root: Literal["synthetic_cases"]


class IntakeContract(BaseModel):
    contract_version: Literal["1.0"]
    authoritative_inputs: AuthoritativeInputs


@dataclass(frozen=True, slots=True)
class CaseManifestError(ValueError):
    subject: str
    reason: str

    def __str__(self) -> str:
        return f"{self.subject}: {self.reason}"


@dataclass(frozen=True, slots=True)
class IntakeCase:
    label: LabelEntry
    split: SplitEntry


def validate_case(case: IntakeCase, checked: frozenset[str]) -> None:
    label, split = case.label, case.split
    if label.model_dump(include=COMMON_FIELDS) != split.model_dump(include=COMMON_FIELDS):
        raise CaseManifestError(label.case_id, "label and split identity fields differ")
    if split.leakage_key != label.case_id:
        raise CaseManifestError(label.case_id, "leakage key must match the case ID")
    if label.eligible_for_production_validation or label.eligible_for_security_incident_statistics:
        raise CaseManifestError(label.case_id, "demo cases cannot be admitted to production metrics")
    if label.synthetic:
        expected = ("synthetic", "synthetic_only", "synthetic_approved", "synthetic_demo", "synthetic_demo_only")
        evidence_root = "synthetic_cases"
    else:
        expected = ("actual_observed", "no", "pending_security_review", "not_assigned",
                    "insufficient_for_supervised_model_evaluation")
        evidence_root = "runtime_cases"
    if (label.data_origin, label.eligible_for_training, label.label_status, split.split, split.split_status) != expected:
        raise CaseManifestError(label.case_id, "invalid demo admission or split")
    if label.synthetic != label.not_actual_incident:
        raise CaseManifestError(label.case_id, "incident provenance conflicts with synthetic status")
    display: str
    match (label.synthetic, label.label):
        case (True, "confirmed_security_incident"):
            display = "simulated_confirmed_security_incident"
        case (True, "policy_blocked"):
            display = "synthetic_policy_blocked"
        case (False, "confirmed_security_incident"):
            raise CaseManifestError(label.case_id, "actual confirmed incidents are outside the demo contract")
        case (_, other):
            display = other
    if label.display_label != display:
        raise CaseManifestError(label.case_id, "invalid display label")
    if len(set(label.evidence_paths)) != len(label.evidence_paths):
        raise CaseManifestError(label.case_id, "duplicate evidence path")
    for name in label.evidence_paths:
        parts = PurePosixPath(name).parts
        if parts[:2] != (evidence_root, label.case_id) or name not in checked:
            raise CaseManifestError(label.case_id, "evidence path is missing or outside its own case")


def load_cases(root: Path) -> tuple[IntakeCase, ...]:
    checked = verified_paths(root, INTAKE)
    try:
        contract = IntakeContract.model_validate_json((root / "training_data_contract.json").read_bytes())
        labels = read_jsonl(root / contract.authoritative_inputs.label_manifest, LabelEntry)
        splits = read_jsonl(root / contract.authoritative_inputs.split_manifest, SplitEntry)
    except (OSError, UnicodeError, ValidationError) as exc:
        raise CaseManifestError("intake", "unreadable manifest or unsupported schema") from exc
    by_label = {item.case_id: item for item in labels}
    by_split = {item.case_id: item for item in splits}
    if len(by_label) != len(labels) or len(by_split) != len(splits):
        raise CaseManifestError("manifests", "duplicate case_id")
    if not by_label or by_label.keys() != by_split.keys():
        raise CaseManifestError("manifests", "nonempty case ID sets must match")
    cases = tuple(IntakeCase(label, by_split[label.case_id]) for label in labels)
    for case in cases:
        validate_case(case, checked)
    return cases
