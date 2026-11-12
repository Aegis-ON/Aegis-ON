from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
from random import Random
from typing import Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from .codebert_input import BASE_REVISION, BASE_SHA256, MAX_COMMAND_CHARS, Encoder, normalize_command, sha256_file, token_ids
from .sysmon import MAX_EVENTS, parse_sysmon

Label = Literal["benign", "review", "unknown"]
Split = Literal["train", "validation", "test"]
SPLITS: tuple[Split, ...] = ("train", "validation", "test")
RATIOS = (0.70, 0.15, 0.15)


class DatasetError(ValueError):
    pass


class EventRow(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True, str_strip_whitespace=True)
    case_id: str = Field(min_length=1)
    source_ref: str = Field(min_length=1)
    scenario_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    System: dict
    EventData: dict


class LabelRow(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True, str_strip_whitespace=True)
    case_id: str = Field(min_length=1)
    label: Label
    evidence_ref: str = Field(min_length=1)
    command_family: str = Field(min_length=1)
    investigation_id: str = Field(min_length=1)


class Case(LabelRow):
    source_ref: str
    scenario_id: str
    run_id: str
    command: str
    status: Literal["eligible", "missing_command", "too_long", "unsupported", "invalid"]


RowT = TypeVar("RowT", bound=BaseModel)
LabelledT = TypeVar("LabelledT", EventRow, LabelRow)


def read_jsonl(path: Path, schema: type[RowT]) -> list[RowT]:
    with path.open(encoding="utf-8") as stream:
        return [schema.model_validate_json(line) for line in stream if line.strip()]


def index_rows(rows: list[LabelledT]) -> dict[str, LabelledT]:
    index = {row.case_id: row for row in rows}
    if len(index) != len(rows):
        raise DatasetError("duplicate case_id")
    return index


def prepare_cases(events: list[EventRow], labels: dict[str, LabelRow], tokenizer: Encoder | None = None) -> list[Case]:
    if set(index_rows(events)) != set(labels):
        raise DatasetError("events and labels must have identical case IDs")
    cases = []
    for start in range(0, len(events), MAX_EVENTS):
        batch = events[start:start + MAX_EVENTS]
        parsed, items = parse_sysmon({"events": [
            {"System": row.System, "EventData": row.EventData} for row in batch
        ]})
        by_id = {event["event_id"]: event for event in parsed}
        for row, item in zip(batch, items, strict=True):
            event = by_id.get(item.get("event_id"))
            status, command = item["status"], ""
            if event is not None:
                if event["source_metadata"]["sysmon_event_id"] != 1:
                    status = "unsupported"
                elif len(event["command_line"]) > MAX_COMMAND_CHARS:
                    status = "too_long"
                else:
                    command = normalize_command(event["command_line"], (event["host"], event["user"]))
                    status = "eligible" if command else "missing_command"
                    if command and tokenizer is not None and token_ids(tokenizer, command) is None:
                        status = "too_long"
            cases.append(Case(
                **labels[row.case_id].model_dump(), source_ref=row.source_ref,
                scenario_id=row.scenario_id, run_id=row.run_id, command=command, status=status,
            ))
    return cases


def connected_groups(cases: list[Case]) -> list[list[Case]]:
    parents = list(range(len(cases)))
    keys: dict[tuple[str, str], int] = {}

    def root(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    for index, case in enumerate(cases):
        values = (case.scenario_id, case.run_id, case.command_family,
                  " ".join(case.command.casefold().split()), case.investigation_id)
        for field, value in zip(("scenario", "run", "family", "command", "investigation"), values, strict=True):
            if value:
                previous = keys.setdefault((field, value), index)
                parents[root(index)] = root(previous)
    groups: dict[int, list[Case]] = defaultdict(list)
    for index, case in enumerate(cases):
        groups[root(index)].append(case)
    return list(groups.values())


def known_labels(cases: list[Case]) -> set[Label]:
    return {case.label for case in cases if case.status == "eligible" and case.label != "unknown"}


def split_cases(cases: list[Case]) -> dict[Split, list[Case]]:
    groups = connected_groups(sorted(cases, key=lambda case: case.case_id))
    Random(101).shuffle(groups)
    groups.sort(key=len)
    pools: dict[frozenset[Label], list[list[Case]]] = defaultdict(list)
    for group in groups:
        pools[frozenset(known_labels(group))].append(group)
    mixed, benign, review = (pools[frozenset(labels)] for labels in
                              (("benign", "review"), ("benign",), ("review",)))
    splits: dict[Split, list[Case]] = {split: [] for split in SPLITS}
    for split in reversed(SPLITS):
        if mixed:
            splits[split].extend(mixed.pop(0))
        elif benign and review:
            splits[split].extend(benign.pop(0) + review.pop(0))
    targets = dict(zip(SPLITS, (len(cases) * ratio for ratio in RATIOS), strict=True))
    for group in sorted((group for pool in pools.values() for group in pool), key=len, reverse=True):
        split = max(SPLITS, key=lambda name: targets[name] - len(splits[name]))
        splits[split].extend(group)
    return {split: sorted(rows, key=lambda case: case.case_id) for split, rows in splits.items()}


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def read_split(path: Path, split: Split) -> tuple[list[Case], bool]:
    audit = json.loads((path.parent / "split-audit.json").read_text(encoding="utf-8"))
    if (audit["eligible"] is not True or type(audit["fixture"]) is not bool
            or audit["splits"][split]["sha256"] != sha256_file(path)):
        raise DatasetError(f"unverified or ineligible {split} split")
    return read_jsonl(path, Case), audit["fixture"]


def prepare(args: argparse.Namespace) -> None:
    weights = args.base / "model.safetensors" if args.base else None
    actual = sha256_file(weights) if weights and weights.is_file() else None
    tokenizer = None
    if args.base and (actual == BASE_SHA256 or (actual and args.fixture)):
        from transformers import AutoTokenizer

        tokenizer = AutoTokenizer.from_pretrained(args.base, local_files_only=True, trust_remote_code=False)
    cases = prepare_cases(read_jsonl(args.events, EventRow), index_rows(read_jsonl(args.labels, LabelRow)), tokenizer)
    splits = split_cases(cases)
    args.out.mkdir(parents=True, exist_ok=False)
    write_json(args.out / "source-audit.json", {
        "format": "Sysmon System/EventData JSONL with independently labelled cases",
        "events_sha256": sha256_file(args.events), "labels_sha256": sha256_file(args.labels),
        "source_refs": sorted({case.source_ref for case in cases}), "rows": len(cases),
        "command_statuses": dict(Counter(case.status for case in cases)),
        "token_limit_checked": tokenizer is not None,
        "weights": {"revision": BASE_REVISION, "expected_sha256": BASE_SHA256, "sha256": actual,
                    "status": "verified" if actual == BASE_SHA256 else "mismatch" if actual else "missing"},
    })
    audit = {}
    for split, rows in splits.items():
        path = args.out / f"{split}.jsonl"
        path.write_text("".join(row.model_dump_json() + "\n" for row in rows), encoding="utf-8")
        audit[split] = {"sha256": sha256_file(path), "rows": len(rows),
                        "labels": dict(Counter(row.label for row in rows)),
                        "known_classes_present": sorted(known_labels(rows))}
    write_json(args.out / "split-audit.json", {
        "fixture": args.fixture, "splits": audit,
        "eligible": all(known_labels(rows) == {"benign", "review"} for rows in splits.values()),
    })


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("prepare")
    for name in ("events", "labels", "out"):
        command.add_argument(f"--{name}", type=Path, required=True)
    command.add_argument("--base", type=Path)
    command.add_argument("--fixture", action="store_true")
    prepare(parser.parse_args())


if __name__ == "__main__":
    main()
