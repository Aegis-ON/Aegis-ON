from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
import hashlib
from threading import Lock
from typing import Any, Callable

from .engine import DetectionPipeline
from .models import Detection, SecurityEvent, validate_unicode
from .privacy import redact_for_display


class DetectionService:
    def __init__(self) -> None:
        self.pipeline = DetectionPipeline()
        self._detections: OrderedDict[str, Detection] = OrderedDict()
        # Keep the conservative display as the stored Detection. An optional
        # sanitized alternate is shown only while its exact host is approved.
        self._host_overrides: dict[str, tuple[bytes, str]] = {}
        self._lock = Lock()

    def analyze(self, raw_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        detections, _ = self.analyze_with_event_refs(raw_events)
        return detections

    def analyze_with_event_refs(
        self, raw_events: list[dict[str, Any]], *, allow_empty_command_line: bool = False,
        mask: Callable[[str], str] | None = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        mask = mask or (lambda value: value)
        events = [SecurityEvent.from_mapping(event, allow_empty_command_line=allow_empty_command_line) for event in raw_events]
        event_ids = [event.event_id for event in events]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("duplicate event_id in request")
        event_refs = redact_for_display([
            {"input_index": index, "event_id": mask(event.event_id)}
            for index, event in enumerate(events)
        ])
        display_ids = [ref["event_id"] for ref in event_refs]
        if len(display_ids) != len(set(display_ids)):
            raise ValueError("duplicate event_id after display redaction")
        detections = self.pipeline.analyze(events)
        # Store only display-safe detection text so later list/approval responses
        # cannot reveal candidate values after the request's mask is discarded.
        host_overrides: dict[str, tuple[bytes, str]] = {}
        for detection in detections:
            original_host = detection.host
            conservative_host = mask(original_host)
            alternate_host = getattr(mask, 'host', mask)(original_host)
            if alternate_host != conservative_host:
                host_overrides[detection.detection_id] = (
                    hashlib.sha256(original_host.encode('utf-8')).digest(), alternate_host)
            detection.host = conservative_host
            detection.event_ids = [mask(value) for value in detection.event_ids]
            detection.evidence = [mask(value) for value in detection.evidence]
        with self._lock:
            for detection in detections:
                self._detections[detection.detection_id] = detection
            self._host_overrides.update(host_overrides)
        return (
            [self._display_detection(detection, host_overrides) for detection in detections],
            event_refs,
        )

    @staticmethod
    def _display_detection(detection: Detection, overrides: dict[str, tuple[bytes, str]]) -> dict[str, Any]:
        value = detection.to_dict()
        override = overrides.get(detection.detection_id)
        if override:
            value['host'] = override[1]
        return redact_for_display(value)

    def _active_overrides(self, hosts: frozenset[str]) -> dict[str, tuple[bytes, str]]:
        hashes = {hashlib.sha256(host.encode('utf-8')).digest() for host in hosts}
        return {key: value for key, value in self._host_overrides.items() if value[0] in hashes}

    def list_detections(self, verified_public_hosts: frozenset[str] = frozenset()) -> list[dict[str, Any]]:
        with self._lock:
            overrides = self._active_overrides(verified_public_hosts)
            return [self._display_detection(item, overrides) for item in reversed(self._detections.values())]

    def approve(self, detection_id: str, analyst: str, rationale: str,
                verified_public_hosts: frozenset[str] = frozenset()) -> dict[str, Any]:
        validate_unicode(analyst, "analyst")
        validate_unicode(rationale, "rationale")
        with self._lock:
            detection = self._detections.get(detection_id)
            if not detection:
                raise KeyError(detection_id)
            if detection.status != "approved_for_simulated_response":
                detection.status = "approved_for_simulated_response"
                detection.evidence.append(f"approved locally by {analyst} at {datetime.now(timezone.utc).isoformat()}")
                if rationale:
                    detection.evidence.append(f"analyst rationale: {rationale}")
            return self._display_detection(detection, self._active_overrides(verified_public_hosts))
