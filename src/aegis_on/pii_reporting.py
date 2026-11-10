"""Build privacy-preserving PII summaries and display replacements per request."""
from __future__ import annotations

import re
from typing import Any

from .pii import PIIDetector, redact_spans
from .privacy import _token

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
    finding_spans = []
    replacements: dict[str, str] = {}
    for index, field, value in fields:
        spans = detector.find(value)
        _, masked = redact_spans(value, spans)
        for merged, token in masked:
            replacements[value[merged.start:merged.end]] = token
        for span in spans:
            # Keep every detected value, including subspans swallowed by an
            # overlap union, so a repeat in another output field is masked too.
            _, individual = redact_spans(value, [span])
            token = individual[0][1]
            raw = value[span.start:span.end]
            replacements.setdefault(raw, token)
            findings.append({"input_index": index, "field": field, "type": span.label,
                             "source": span.source, "token": token})
            finding_spans.append((value, span))
    # Look ahead at every position so matches starting inside another candidate
    # are not skipped. Longer alternatives at the same position cover shorter ones.
    ordered = sorted(replacements, key=lambda item: (-len(item), item))
    if len(ordered) > 5000:
        raise ValueError("PII analysis exceeds the candidate limit")
    pattern = re.compile("(?=(" + "|".join(map(re.escape, ordered)) + "))") if ordered else None

    def mask_segments(text: str) -> list[tuple[int, int, str]]:
        if not pattern:
            return []
        matches = [(match.start(), match.start() + len(match.group(1)), replacements[match.group(1)])
                   for match in pattern.finditer(text)]
        merged: list[tuple[int, int, str]] = []
        for start, end, token in matches:
            if merged and start < merged[-1][1]:
                prev_start, prev_end, prev_token = merged[-1]
                if end > prev_end:
                    merged[-1] = (prev_start, end, _token('PII', text[prev_start:end], 'aegis-on-demo'))
            else:
                merged.append((start, end, token))
        return merged

    def mask(text: str) -> str:
        parts, position = [], 0
        for start, end, token in mask_segments(text):
            parts.extend((text[position:start], token))
            position = end
        parts.append(text[position:])
        return ''.join(parts)

    # The final output can include overlaps discovered in other event fields.
    # Reflect that actual union token in each finding without including raw text.
    segment_cache: dict[str, list[tuple[int, int, str]]] = {}
    for finding, (value, span) in zip(findings, finding_spans):
        if value not in segment_cache:
            segment_cache[value] = mask_segments(value)
        finding['display_token'] = next(token for start, end, token in segment_cache[value]
                                        if start <= span.start and end >= span.end)

    return {**detector.status(), "findings": findings[:MAX_REPORTED_FINDINGS],
            "truncated": len(findings) > MAX_REPORTED_FINDINGS}, mask
