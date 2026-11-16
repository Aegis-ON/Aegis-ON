from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path

from pydantic import TypeAdapter

from .codebert_data import Case, DatasetError, EventRow, Split, index_rows, read_jsonl, read_split, write_json
from .codebert_input import sha256_file
from .engine import DetectionPipeline
from .models import SecurityEvent
from .review_priority import Candidate
from .sysmon import parse_sysmon


def replay_candidates(events_path: Path, split_path: Path, split: Split) -> list[Candidate]:
    cases, _ = read_split(split_path, split)
    source_audit = json.loads((split_path.parent / "source-audit.json").read_text(encoding="utf-8"))
    if source_audit["events_sha256"] != sha256_file(events_path):
        raise DatasetError("replay log differs from audited events")
    events = index_rows(read_jsonl(events_path, EventRow))
    selected = {case.case_id: case for case in cases}
    batches: dict[tuple[str, str], list[EventRow]] = defaultdict(list)
    for case_id, event in events.items():
        case = selected.get(case_id)
        if case is not None:
            batches[(case.scenario_id, case.run_id)].append(event)
    pipeline = DetectionPipeline()
    candidates: list[Candidate] = []
    for batch in batches.values():
        parsed, items = parse_sysmon({"events": [
            {"System": row.System, "EventData": row.EventData} for row in batch
        ]})
        case_ids = {item["event_id"]: batch[item["input_index"]].case_id
                    for item in items if item["status"] == "processed"}
        detections = pipeline.analyze([SecurityEvent.from_mapping(
            event, allow_empty_command_line=True) for event in parsed])
        for ordinal, detection in enumerate(detections):
            refs = tuple(case_ids[event_id] for event_id in detection.event_ids)
            identity = json.dumps([detection.technique, ordinal, refs], separators=(",", ":"))
            candidates.append(Candidate(
                detection_id=hashlib.sha256(identity.encode()).hexdigest(), event_ids=refs,
                source=detection.source.value, score=detection.score,
                requires_human_approval=detection.requires_human_approval,
            ))
    return sorted(candidates, key=lambda candidate: -candidate.score)


def save_candidates(path: Path, candidates: list[Candidate], split_path: Path) -> None:
    write_json(path, {"split_sha256": sha256_file(split_path),
                      "candidates": [row.model_dump(mode="json") for row in candidates]})


def load_candidates(path: Path, split_path: Path, cases: list[Case]) -> list[Candidate]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data["split_sha256"] != sha256_file(split_path):
        raise DatasetError("candidates do not belong to the supplied split")
    candidates = TypeAdapter(list[Candidate]).validate_python(data["candidates"])
    ids = {case.case_id for case in cases}
    if (len({row.detection_id for row in candidates}) != len(candidates)
            or any(not row.event_ids or not set(row.event_ids) <= ids for row in candidates)):
        raise DatasetError("invalid candidate IDs or event references")
    return candidates
