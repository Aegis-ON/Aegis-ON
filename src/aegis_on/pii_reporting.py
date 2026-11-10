"""Build privacy-preserving PII summaries and display replacements per request."""
from __future__ import annotations

import re
from datetime import datetime, timezone
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


def inspect_events(events: list[dict[str, Any]], indices: list[int], detector: PIIDetector,
                   *, verified_public_hosts: frozenset[str] = frozenset()):
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
    candidate_types: dict[str, set[str]] = {}
    host_direct: dict[str, list[tuple[int, int]]] = {}
    for index, field, value in fields:
        spans = detector.find(value)
        if field == 'host':
            host_direct.setdefault(value, []).extend((span.start, span.end) for span in spans)
        _, masked = redact_spans(value, spans)
        for merged, token in masked:
            replacements[value[merged.start:merged.end]] = token
        for span in spans:
            # Keep every detected value, including subspans swallowed by an
            # overlap union, so a repeat in another output field is masked too.
            _, individual = redact_spans(value, [span])
            token = individual[0][1]
            raw = value[span.start:span.end]
            candidate_types.setdefault(raw.casefold(), set()).add(span.label)
            replacements.setdefault(raw, token)
            findings.append({"input_index": index, "field": field, "type": span.label,
                             "source": span.source, "token": token})
            finding_spans.append((value, span))
    # Look ahead at every position so matches starting inside another candidate
    # are not skipped. Longer alternatives at the same position cover shorter ones.
    # Correlation evidence serializes parsed event times using isoformat(), so a
    # detected timestamp may reappear with Z rewritten to +00:00 (or a UTC
    # suffix added). Associate that spelling with the original candidate token.
    for raw, token in list(replacements.items()):
        if len(raw) < 8:
            continue
        try:
            timestamp = datetime.fromisoformat(raw.replace('Z', '+00:00'))
        except ValueError:
            continue
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        replacements.setdefault(timestamp.isoformat(), token)
    ordered = sorted(replacements, key=lambda item: (-len(item), item))
    if len(ordered) > 5000:
        raise ValueError("PII analysis exceeds the candidate limit")
    pattern = re.compile("(?=(" + "|".join(map(re.escape, ordered)) + "))", re.IGNORECASE) if ordered else None
    by_casefold: dict[str, str] = {}
    for raw in ordered:
        by_casefold.setdefault(raw.casefold(), replacements[raw])

    def replacement_for(matched: str) -> str:
        token = by_casefold.get(matched.casefold())
        if token is not None:
            return token
        # Python's Unicode IGNORECASE includes a few special cases whose
        # casefold strings differ (for example dotted/dotless I). Preserve
        # privacy for those matches without ever returning the raw value.
        for raw in ordered:
            if re.fullmatch(re.escape(raw), matched, re.IGNORECASE):
                return replacements[raw]
        raise ValueError('PII replacement lookup failed')

    def mask_segments(text: str, *, host: bool = False) -> list[tuple[int, int, str]]:
        if not pattern:
            return []
        matches = []
        for match in pattern.finditer(text):
            raw = match.group(1)
            start, end = match.start(), match.start() + len(raw)
            # Only an operator-verified exact host can opt out, and only for
            # a propagated one-syllable Korean surname embedded in a longer
            # word. Direct detections and conflicting PII types always win.
            embedded = ((start > 0 and text[start - 1].isalnum())
                        or (end < len(text) and text[end].isalnum()))
            directly_detected = any(a < end and start < b for a, b in host_direct.get(text, ()))
            if (host and text in verified_public_hosts and embedded and len(raw) == 1
                    and '\uac00' <= raw <= '\ud7a3'
                    and candidate_types.get(raw.casefold()) == {'SURNAME'} and not directly_detected):
                continue
            matches.append((start, end, replacement_for(raw)))
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
        return render(text, host=False)

    def render(text: str, *, host: bool) -> str:
        parts, position = [], 0
        for start, end, token in mask_segments(text, host=host):
            parts.extend((text[position:start], token))
            position = end
        parts.append(text[position:])
        return ''.join(parts)

    # A separate host-only entry point prevents the exception from affecting
    # event identifiers, evidence, commands, or analyst approval text.
    mask.host = lambda text: render(text, host=True)

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
