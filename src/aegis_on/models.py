from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4


class DetectionSource(StrEnum):
    RULE = "rule"
    SEMANTIC_BASELINE = "semantic-baseline"
    CORRELATION = "correlation"


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: datetime
    host: str
    user: str
    process: str
    command_line: str
    parent_process: str = ""
    destination: str = ""
    event_id: str = field(default_factory=lambda: str(uuid4()))

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "SecurityEvent":
        required = ("timestamp", "host", "user", "process", "command_line")
        absent = [key for key in required if not value.get(key)]
        if absent:
            raise ValueError(f"missing required event fields: {', '.join(absent)}")

        raw_timestamp = value["timestamp"]
        timestamp = (
            raw_timestamp
            if isinstance(raw_timestamp, datetime)
            else datetime.fromisoformat(str(raw_timestamp).replace("Z", "+00:00"))
        )
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        return cls(
            timestamp=timestamp,
            host=str(value["host"]),
            user=str(value["user"]),
            process=str(value["process"]),
            command_line=str(value["command_line"]),
            parent_process=str(value.get("parent_process", "")),
            destination=str(value.get("destination", "")),
            event_id=str(value.get("event_id") or uuid4()),
        )


@dataclass
class Detection:
    technique: str
    title: str
    score: int
    source: DetectionSource
    evidence: list[str]
    event_ids: list[str]
    host: str
    requires_human_approval: bool = False
    status: str = "pending_review"
    detection_id: str = field(default_factory=lambda: str(uuid4()))

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["source"] = self.source.value
        return data
