"""Conservative, read-only endpoint observations derived from sanitized history.

A pseudonym is not a device identifier. Groups are scoped to one analysis,
never merged across batches. All inputs come from the existing sanitized store.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any


def _group_id(analysis_id: str, kind: str, key: str) -> str:
    return hashlib.sha256(('aegis-observation-v1\0' + analysis_id + '\0' + kind + '\0' + key).encode()).hexdigest()


def _last_seen(events: list[dict[str, Any]]) -> str | None:
    candidates = []
    for event in events:
        value = event.get('timestamp')
        if not isinstance(value, str):
            continue
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            if parsed.tzinfo is None:
                continue
            candidates.append((parsed.astimezone(timezone.utc), value))
        except (ValueError, OverflowError):
            continue
    return max(candidates, default=(None, None), key=lambda item: item[0])[1]


def build_endpoint_groups(analyses: list[dict[str, Any]], detections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Derive observation groups without storing new raw or pseudonymous data.

    Sysmon events carry a sanitized host; JSON history records only event IDs.
    For JSON, only references associated with a detection can be attributed,
    and a reference claimed by more than one host is left unassigned.
    """
    by_id = {d.get('detection_id'): d for d in detections if isinstance(d, dict)}
    output: list[dict[str, Any]] = []
    for batch in analyses:
        analysis_id = batch.get('analysis_id')
        if not isinstance(analysis_id, str) or not analysis_id:
            continue
        kind = batch.get('input_type')
        relevant = [by_id[id_] for id_ in batch.get('detection_ids', []) if id_ in by_id]
        groups: dict[tuple[str, str], dict[str, Any]] = {}

        def group(category: str, key: str, host: str | None, certainty: str) -> dict[str, Any]:
            group_key = (category, key)
            if group_key not in groups:
                groups[group_key] = {
                    'endpoint_id': _group_id(analysis_id, category, key),
                    'analysis_id': analysis_id, 'input_type': kind,
                    'analyzed_at': batch.get('analyzed_at'), 'host': host,
                    'identity_scope': 'single_analysis', 'attribution': certainty,
                    'events': [], 'detections': [],
                }
            return groups[group_key]

        if kind == 'sysmon':
            sources = batch.get('source_events') or []
            for i, source in enumerate(sources):
                if not isinstance(source, dict):
                    continue
                host = source.get('host')
                if isinstance(host, str) and host:
                    target = group('host', host, host, 'source_metadata')
                else:
                    # Missing hosts cannot establish that two events are from the same device.
                    target = group('unknown_event', str(i), None, 'unknown')
                target['events'].append(source)
            for detection in relevant:
                event_ids = set(detection.get('event_ids') or [])
                matches = [g for g in groups.values() if any(e.get('event_id') in event_ids for e in g['events'])]
                if not matches:
                    ident = str(detection.get('detection_id', ''))
                    matches = [group('unlinked_detection', ident, None, 'unknown')]
                for target in matches:
                    target['detections'].append(detection)
        elif kind == 'json':
            refs = {e.get('event_id'): e for e in batch.get('event_refs', [])
                    if isinstance(e, dict) and isinstance(e.get('event_id'), str)}
            owners: dict[str, set[tuple[str, str]]] = {}
            for detection in relevant:
                host = detection.get('host')
                ident = str(detection.get('detection_id', ''))
                group_key = ('host', host) if isinstance(host, str) and host else ('unknown_detection', ident)
                target = group(group_key[0], group_key[1], host if group_key[0] == 'host' else None,
                               'detection_reference' if group_key[0] == 'host' else 'unknown')
                target['detections'].append(detection)
                for event_id in detection.get('event_ids') or []:
                    if event_id in refs:
                        owners.setdefault(event_id, set()).add(group_key)
            for event_id, ref in refs.items():
                group_keys = owners.get(event_id, set())
                if len(group_keys) == 1:
                    groups[next(iter(group_keys))]['events'].append(ref)
                else:
                    # No host in legacy event_refs; do not join unobserved or
                    # ambiguous references merely because they share a batch.
                    group('unknown_event', event_id, None, 'unknown')['events'].append(ref)
        for item in groups.values():
            item['event_count'] = len(item['events'])
            item['detection_count'] = len(item['detections'])
            scores = [d.get('score') for d in item['detections'] if type(d.get('score')) in (float, int)]
            item['highest_score'] = max(scores) if scores else None
            item['last_seen'] = _last_seen(item['events'])
            output.append(item)
    return output
