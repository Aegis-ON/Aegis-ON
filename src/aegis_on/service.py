from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any

from .engine import DetectionPipeline
from .models import Detection, SecurityEvent
from .privacy import redact_for_display


class DetectionService:
    def __init__(self) -> None:
        self.pipeline = DetectionPipeline()
        self._detections: OrderedDict[str, Detection] = OrderedDict()

    def analyze(self, raw_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        detections, _ = self.analyze_with_event_refs(raw_events)
        return detections

    def analyze_with_event_refs(
        self, raw_events: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        events = [SecurityEvent.from_mapping(event) for event in raw_events]
        event_ids = [event.event_id for event in events]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("duplicate event_id in request")
        event_refs = redact_for_display([
            {"input_index": index, "event_id": event.event_id}
            for index, event in enumerate(events)
        ])
        display_ids = [ref["event_id"] for ref in event_refs]
        if len(display_ids) != len(set(display_ids)):
            raise ValueError("duplicate event_id after display redaction")
        detections = self.pipeline.analyze(events)
        for detection in detections:
            self._detections[detection.detection_id] = detection
        return (
            [redact_for_display(detection.to_dict()) for detection in detections],
            event_refs,
        )

    def list_detections(self) -> list[dict[str, Any]]:
        return [redact_for_display(item.to_dict()) for item in reversed(self._detections.values())]

    def approve(self, detection_id: str, analyst: str, rationale: str) -> dict[str, Any]:
        detection = self._detections.get(detection_id)
        if not detection:
            raise KeyError(detection_id)
        detection.status = "approved_for_simulated_response"
        detection.evidence.append(f"approved locally by {analyst} at {datetime.now(timezone.utc).isoformat()}")
        if rationale:
            detection.evidence.append(f"analyst rationale: {rationale}")
        return redact_for_display(detection.to_dict())
