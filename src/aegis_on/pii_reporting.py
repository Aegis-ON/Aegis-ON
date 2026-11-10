"""Build privacy-preserving PII summaries and display replacements per request."""
from __future__ import annotations

import re
from typing import Any

from .pii import PIIDetector, redact_spans

# Only fields used by the existing normalizer and detection engine are scanned.
# Unknown keys, metadata keys and non-string values are not presented as covered.
FIELDS = ("host", "user", "process", "command_line", "parent_process", "process_path",
          "parent_process_path", "parent_command_line", "source_ip", "destination", "event_id")
MAX_MODEL_CHARS = 250_000
MAX_REPORTED_FINDINGS = 500


class InvalidPIIInput(ValueError):
    """An event field would be coerced to unscanned text by the analyzer."""


def inspect_events(events: list[dict[str, Any]], indices: list[int], detector: PIIDetector):
    """Return sanitized summaries and a pure replacement function, never raw text."""
    for event in events:
        for field in FIELDS:
            value = event.get(field)
            if value is not None and not isinstance(value, str):
                raise InvalidPIIInput("event text field must be a string")
            if isinstance(value, str) and any(0xD800 <= ord(char) <= 0xDFFF for char in value):
                raise InvalidPIIInput("invalid event text")
    fields = [(index, field, event.get(field)) for index, event in zip(indices, events)
              for field in FIELDS if isinstance(event.get(field), str) and event.get(field)]
    if detector.status()["state"] == "ready" and sum(len(value) for _, _, value in fields) > MAX_MODEL_CHARS:
        raise ValueError("PII analysis input exceeds the configured character limit")
    findings: list[dict[str, Any]] = []
    replacements: dict[str, str] = {}
    for index, field, value in fields:
        spans = detector.find(value)
        _, masked = redact_spans(value, spans)
        for merged, token in masked:
            replacements[value[merged.start:merged.end]] = token
        for span in spans:
            token = next(token for merged, token in masked
                         if merged.start <= span.start and merged.end >= span.end)
            findings.append({"input_index": index, "field": field, "type": span.label,
                             "source": span.source, "token": token})
    # Longest matches first prevent partially exposing overlapping candidates.
    ordered = sorted(replacements, key=lambda item: (-len(item), item))
    if len(ordered) > 5000:
        raise ValueError("PII analysis exceeds the candidate limit")
    pattern = re.compile("|".join(map(re.escape, ordered))) if ordered else None

    def mask(text: str) -> str:
        return pattern.sub(lambda match: replacements[match.group()], text) if pattern else text

    return {**detector.status(), "findings": findings[:MAX_REPORTED_FINDINGS],
            "truncated": len(findings) > MAX_REPORTED_FINDINGS}, mask
