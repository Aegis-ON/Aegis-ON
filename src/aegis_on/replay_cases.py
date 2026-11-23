from pathlib import Path
from typing import Final

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from pydantic import JsonValue, TypeAdapter, ValidationError

from .case_intake_inventory import PackageIntegrityError
from .case_manifest import CaseManifestError, load_cases

ROOT: Final = Path(__file__).resolve().parents[2]
REPLAY_SOC_FIXTURE: Final = ROOT / "data" / "replay_soc_fixture.json"
CASE_INTAKE_ROOT: Final = ROOT / "datasets" / "agent_framework_eval_intake_2026-11-21"
SNAPSHOT: Final = TypeAdapter(dict[str, JsonValue])


def replay_summary_response() -> JSONResponse:
    try:
        payload = SNAPSHOT.validate_json(REPLAY_SOC_FIXTURE.read_bytes())
    except (OSError, ValidationError):
        raise HTTPException(status_code=503, detail="replay snapshot unavailable") from None

    try:
        cases = load_cases(CASE_INTAKE_ROOT)
    except (CaseManifestError, PackageIntegrityError):
        payload["case_intake_status"] = "unavailable"
        payload["case_governance"] = {}
    else:
        payload["case_intake_status"] = "available"
        payload["case_governance"] = {
            case.label.case_id: {
                **case.label.model_dump(mode="json", exclude={"label", "case_id"}),
                "split": case.split.split,
                "split_status": case.split.split_status,
            }
            for case in cases
        }
    return JSONResponse(payload, headers={"Cache-Control": "no-store"})
