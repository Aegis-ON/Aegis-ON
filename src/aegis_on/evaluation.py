"""Reproducible synthetic case evaluation; this is not an attack-detection benchmark.

The adapter receives only normalized input events and a task name, never case
labels. PII evaluation is outside this contract. No event is executed and no
network call is made. Use --help for the local JSON CLI.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, Sequence

from .engine import DetectionPipeline
from .models import SecurityEvent
from .sysmon import parse_sysmon

TASKS = {"command_behavior": "event", "fanout_condition": "batch"}
LABELS = {"positive", "negative", "unknown"}
TECHNIQUES = {"T1105", "T1485", "T1489", "T1059"}
SPLITS = {"dev", "eval"}


@dataclass(frozen=True)
class Prediction:
    technique: str
    source: str
    event_ids: tuple[str, ...]
    score: float | int | None = None
    evidence: tuple[str, ...] = ()


class EvaluationAdapter(Protocol):
    name: str
    command_sources: tuple[str, ...]
    fanout_sources: tuple[str, ...]

    def predict(self, events: Sequence[SecurityEvent], task: str) -> Sequence[Prediction]: ...


class AegisAdapter:
    """Current production rules, heuristic baseline, and correlation engine."""
    name = "aegis-native"
    command_sources = ("rule", "semantic-baseline")
    fanout_sources = ("correlation",)

    def __init__(self) -> None:
        self.pipeline = DetectionPipeline()

    def predict(self, events: Sequence[SecurityEvent], task: str) -> Sequence[Prediction]:
        return [Prediction(d.technique, d.source.value, tuple(d.event_ids), d.score, tuple(d.evidence))
                for d in self.pipeline.analyze(list(events))]


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("dataset must contain valid JSON values") from exc


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError("non-finite JSON value")


def _required_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a nonempty string")
    if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ValueError(f"{field} must be valid Unicode")
    return value


def validate_dataset(dataset: Any) -> None:
    """Validate annotations and detect exact cross-split leaks.

    Exact event JSON and case-insensitive, whitespace-normalized commands are
    checked. Group separation is still required for related nonidentical cases.
    """
    if not isinstance(dataset, dict) or type(dataset.get("schema_version")) is not int or dataset["schema_version"] != 1:
        raise ValueError("schema_version must be 1")
    _required_string(dataset.get("dataset_id"), "dataset_id")
    cases = dataset.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("cases must be a nonempty array")
    ids: set[str] = set()
    groups: dict[str, str] = {}
    event_hashes: dict[str, str] = {}
    commands: dict[str, str] = {}
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("case must be an object")
        case_id = _required_string(case.get("case_id"), "case_id")
        if case_id in ids:
            raise ValueError("duplicate case_id")
        ids.add(case_id)
        group = _required_string(case.get("group_id"), "group_id")
        split = case.get("split")
        if not isinstance(split, str) or split not in SPLITS:
            raise ValueError("split must be dev or eval")
        if group in groups and groups[group] != split:
            raise ValueError("group_id appears in both splits")
        groups[group] = split
        task = case.get("task")
        if not isinstance(task, str) or task not in TASKS or case.get("unit") != TASKS[task]:
            raise ValueError("invalid task or unit")
        if not isinstance(case.get("truth"), str) or case["truth"] not in LABELS:
            raise ValueError("invalid truth")
        if not isinstance(case.get("context"), str) or case["context"] not in {"benign", "suspicious", "unknown"}:
            raise ValueError("invalid context")
        _required_string(case.get("truth_reason"), "truth_reason")
        _required_string(case.get("expected_engine_behavior"), "expected_engine_behavior")
        if case.get("synthetic") is not True:
            raise ValueError("all cases must be marked synthetic")
        technique_truth = case.get("technique_truth")
        if not isinstance(technique_truth, dict) or any(
            key not in TECHNIQUES or not isinstance(value, str) or value not in LABELS
            for key, value in technique_truth.items()
        ):
            raise ValueError("invalid technique_truth")
        if task == "fanout_condition" and technique_truth:
            raise ValueError("technique_truth is only supported for event cases")
        events = case.get("events")
        if not isinstance(events, list) or not events or len(events) > 1000:
            raise ValueError("events must contain 1 to 1000 records")
        if case["unit"] == "event" and len(events) != 1:
            raise ValueError("event cases require exactly one record")
        for event in events:
            digest = hashlib.sha256(_canonical(event)).hexdigest()
            if digest in event_hashes and event_hashes[digest] != split:
                raise ValueError("exact input event appears in both splits")
            event_hashes[digest] = split
            data = event.get("EventData") if isinstance(event, dict) else None
            command = data.get("CommandLine") if isinstance(data, dict) else None
            if isinstance(command, str):
                normalized = " ".join(command.casefold().split())
                if normalized:
                    if normalized in commands and commands[normalized] != split:
                        raise ValueError("normalized command appears in both splits")
                    commands[normalized] = split
    _canonical(dataset)


def _metric(numerator: int, denominator: int, reason: str) -> dict[str, Any]:
    return {"value": numerator / denominator if denominator else None,
            "numerator": numerator, "denominator": denominator,
            "undefined_reason": None if denominator else reason}


def _metrics(records: list[tuple[str, bool, bool]]) -> dict[str, Any]:
    cases: dict[str, list[str]] = {key: [] for key in ("tp", "fp", "tn", "fn")}
    for case_id, truth, prediction in records:
        key = ("tp" if prediction else "fn") if truth else ("fp" if prediction else "tn")
        cases[key].append(case_id)
    tp, fp, tn, fn = (len(cases[key]) for key in ("tp", "fp", "tn", "fn"))
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "support": len(records), "positive_support": tp + fn, "negative_support": tn + fp,
        "precision": _metric(tp, tp + fp, "no predicted positives"),
        "recall": _metric(tp, tp + fn, "no annotated positives"),
        "f1": _metric(2 * tp, 2 * tp + fp + fn, "no positive truth or predictions"),
        "case_ids": cases,
    }


def _prediction_dict(prediction: Prediction) -> dict[str, Any]:
    return {"technique": prediction.technique, "source": prediction.source,
            "event_ids": list(prediction.event_ids), "score": prediction.score,
            "evidence": list(prediction.evidence)}


def evaluate_dataset(dataset: Any, *, split: str, adapter: EvaluationAdapter | None = None,
                     dataset_sha256: str | None = None) -> dict[str, Any]:
    """Evaluate a selected split. Labels remain outside the prediction adapter."""
    validate_dataset(dataset)
    if split not in SPLITS:
        raise ValueError("split must be dev or eval")
    adapter = adapter if adapter is not None else AegisAdapter()
    rows: list[dict[str, Any]] = []
    for case in sorted((c for c in dataset["cases"] if c["split"] == split), key=lambda c: c["case_id"]):
        raw, items = parse_sysmon({"events": case["events"]})
        invalid_items = [{"input_index": item["input_index"], "status": item["status"], "reason": item.get("reason", "")}
                         for item in items if item["status"] != "processed"]
        expected_event_id = 1 if case["task"] == "command_behavior" else 3
        processed_items = (item for item in items if item["status"] == "processed")
        for event, item in zip(raw, processed_items):
            if event["source_metadata"]["sysmon_event_id"] != expected_event_id:
                invalid_items.append({"input_index": item["input_index"], "status": "invalid",
                                      "reason": f"{case['task']} requires Sysmon Event ID {expected_event_id}"})
        invalid_items.sort(key=lambda item: item["input_index"])
        row: dict[str, Any] = {
            "case_id": case["case_id"], "group_id": case["group_id"], "unit": case["unit"],
            "task": case["task"], "context": case["context"], "truth": case["truth"],
            "truth_reason": case["truth_reason"], "technique_truth": case["technique_truth"],
            "expected_engine_behavior": case["expected_engine_behavior"], "input_count": len(case["events"]),
            "processed_count": len(raw), "input_errors": invalid_items, "input_event_refs": [],
        }
        if invalid_items:
            row.update(status="excluded_invalid_input", predictions=[], predicted_positive=None)
            rows.append(row)
            continue
        # Derive stable IDs exclusively from input events and position. Case IDs,
        # group IDs, and annotations may encode ground truth and must not reach
        # the adapter, even indirectly as a readable event identifier.
        normalized_inputs = [{key: value for key, value in event.items() if key != "event_id"} for event in raw]
        input_digest = hashlib.sha256(_canonical(normalized_inputs)).hexdigest()
        for index, event in enumerate(raw):
            opaque = hashlib.sha256(f"{input_digest}:{index}".encode("ascii")).hexdigest()
            event["event_id"] = "evt-" + opaque
            row["input_event_refs"].append({"input_index": index, "event_id": event["event_id"]})
        try:
            events = [SecurityEvent.from_mapping(event, allow_empty_command_line=True) for event in raw]
        except (ValueError, TypeError, OverflowError):
            row.update(status="excluded_invalid_input", predictions=[], predicted_positive=None,
                       input_errors=[{"status": "invalid", "reason": "normalized event invalid"}])
            rows.append(row)
            continue
        predictions = list(adapter.predict(events, case["task"]))
        allowed_sources = adapter.command_sources if case["task"] == "command_behavior" else adapter.fanout_sources
        predictions.sort(key=lambda p: (p.source, p.technique, tuple(p.event_ids), str(p.score), tuple(p.evidence)))
        row.update(status="excluded_unknown_truth" if case["truth"] == "unknown" else "evaluated",
                   predictions=[_prediction_dict(p) for p in predictions],
                   predicted_positive=any(p.source in allowed_sources for p in predictions))
        rows.append(row)

    task_results: dict[str, Any] = {}
    for task in TASKS:
        relevant = [row for row in rows if row["task"] == task]
        scored = [row for row in relevant if row["status"] == "evaluated"]
        sources = adapter.command_sources if task == "command_behavior" else adapter.fanout_sources
        def entries(subset: list[dict[str, Any]], source: str | None = None) -> list[tuple[str, bool, bool]]:
            return [(r["case_id"], r["truth"] == "positive",
                     r["predicted_positive"] if source is None else any(p["source"] == source for p in r["predictions"]))
                    for r in subset]
        task_results[task] = {
            "case_count": len(relevant),
            "excluded_invalid_input": sum(r["status"] == "excluded_invalid_input" for r in relevant),
            "excluded_unknown_truth": sum(r["status"] == "excluded_unknown_truth" for r in relevant),
            "overall": _metrics(entries(scored)),
            "by_source": {source: _metrics(entries(scored, source)) for source in sources},
            "by_context": {context: _metrics(entries([r for r in scored if r["context"] == context]))
                           for context in ("benign", "suspicious", "unknown")},
            "benign_context_alerts": [
                {"case_id": r["case_id"], "truth": r["truth"],
                 "sources": sorted({p["source"] for p in r["predictions"] if p["source"] in sources})}
                for r in relevant if r["context"] == "benign" and r["predicted_positive"] is True
            ],
        }

    technique_results: dict[str, Any] = {}
    event_rows = [r for r in rows if r["unit"] == "event"]
    for technique in sorted(TECHNIQUES):
        annotated = [r for r in event_rows if r["status"] != "excluded_invalid_input"
                     and r["technique_truth"].get(technique) in ("positive", "negative")]
        def technique_entries(source: str | None = None) -> list[tuple[str, bool, bool]]:
            return [(r["case_id"], r["technique_truth"][technique] == "positive",
                     any(p["technique"] == technique and p["source"] in adapter.command_sources
                         and (source is None or p["source"] == source) for p in r["predictions"]))
                    for r in annotated]
        technique_results[technique] = {
            "overall": _metrics(technique_entries()),
            "by_source": {source: _metrics(technique_entries(source)) for source in adapter.command_sources},
            "excluded_invalid_input": sum(r["status"] == "excluded_invalid_input" for r in event_rows),
            "excluded_unknown_annotation": sum(r["technique_truth"].get(technique) == "unknown"
                                               for r in event_rows if r["status"] != "excluded_invalid_input"),
            "excluded_unannotated": sum(technique not in r["technique_truth"]
                                         for r in event_rows if r["status"] != "excluded_invalid_input"),
        }
    return {
        "schema_version": 1, "dataset_id": dataset["dataset_id"], "split": split,
        "dataset_sha256": dataset_sha256 or hashlib.sha256(_canonical(dataset)).hexdigest(),
        "dataset_hash_basis": "file bytes" if dataset_sha256 else "canonical JSON",
        "adapter": adapter.name,
        "interpretation": {"command_behavior": "annotated synthetic triage condition, not real-world attack performance",
                           "fanout_condition": "observed connection condition only; not proof of scan or attack",
                           "techniques": "annotated behavior signals only; technique labels do not establish malicious activity or an ATT&CK attack",
                           "pii": "not evaluated"},
        "tasks": task_results, "techniques": technique_results, "cases": rows,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate annotated synthetic Sysmon cases locally.")
    parser.add_argument("--dataset", required=True, help="UTF-8 JSON dataset path")
    parser.add_argument("--split", required=True, choices=sorted(SPLITS))
    parser.add_argument("--output", help="optional output JSON path; otherwise stdout")
    args = parser.parse_args(argv)
    try:
        data = Path(args.dataset).read_bytes()
        dataset = json.loads(data.decode("utf-8-sig"), object_pairs_hook=_unique_json_object,
                             parse_constant=_reject_nonfinite)
        report = evaluate_dataset(dataset, split=args.split, dataset_sha256=hashlib.sha256(data).hexdigest())
        rendered = json.dumps(report, ensure_ascii=True, indent=2, allow_nan=False) + "\n"
        if args.output:
            Path(args.output).write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    except (ValueError, OSError, UnicodeDecodeError, RecursionError) as exc:
        parser.exit(2, f"evaluation error: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
