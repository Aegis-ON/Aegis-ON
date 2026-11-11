"""Bounded, allowlisted authentication observations; no raw credentials retained."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from uuid import uuid4

FIELDS = {'event_id', 'timestamp', 'host', 'account', 'source_ip', 'outcome'}


def _digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def normalize_auth(payload, collector):
    if not isinstance(payload, dict) or set(payload) != {'events'}:
        raise ValueError('invalid auth batch')
    records = payload['events']
    if not isinstance(records, list) or not 1 <= len(records) <= 1000:
        raise ValueError('invalid auth batch')
    events, entries, seen = [], [], set()
    for index, record in enumerate(records):
        if not isinstance(record, dict) or set(record) != FIELDS:
            raise ValueError('invalid auth record')
        if any(not isinstance(record[k], str) or not record[k] or len(record[k]) > 256 or
               any(0xD800 <= ord(c) <= 0xDFFF for c in record[k]) for k in FIELDS):
            raise ValueError('invalid auth record')
        if record['outcome'] not in ('success', 'failure'):
            raise ValueError('invalid auth outcome')
        timestamp = datetime.fromisoformat(record['timestamp'].replace('Z', '+00:00'))
        if timestamp.tzinfo is None:
            raise ValueError('timestamp must have offset')
        timestamp = timestamp.astimezone(timezone.utc)
        address = ipaddress.ip_address(record['source_ip'])
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        event_key = _digest(['auth-v1', collector, record['event_id']])
        if event_key in seen:
            raise ValueError('duplicate event id')
        seen.add(event_key)
        host_key = _digest([collector, record['host'].casefold()])
        # Group only by explicit same collector, host, account and address.
        group = _digest(['auth-group-v1', collector, record['host'].casefold(), record['account'], str(address)])
        event_id = 'auth-' + event_key
        events.append({'input_index': index, 'event_id': event_id, 'timestamp': timestamp.isoformat(),
                       'host': '[HOST:' + host_key[:10] + ']', 'log_source': 'auth-normalized',
                       'outcome': record['outcome'], 'endpoint_group': host_key, 'group': group})
        entries.append({'event_key': event_key, 'fingerprint': 'full-v1:' + _digest(record), 'host_key': host_key,
                        'occurred': timestamp.isoformat(), 'destination_key': None, 'outbound': False,
                        'event_id': event_id, 'host_display': ''})
    return events, entries


def correlate_auth(events):
    """Same-batch repeated failures followed by success; this is not proof of compromise."""
    groups = {}
    for event in events:
        groups.setdefault(event['group'], []).append(event)
    detections = []
    for items in groups.values():
        items.sort(key=lambda e: (e['timestamp'], e['input_index']))
        failures = []
        for event in items:
            when = datetime.fromisoformat(event['timestamp'])
            failures = [f for f in failures if when - datetime.fromisoformat(f['timestamp']) <= timedelta(minutes=10)]
            if event['outcome'] == 'failure':
                failures.append(event)
            elif len([f for f in failures if f['timestamp'] < event['timestamp']]) >= 3:
                # Equal timestamps alone cannot establish which happened first.
                related = [f for f in failures if f['timestamp'] < event['timestamp']] + [event]
                detections.append({'technique': 'authentication-review', 'title': 'Repeated authentication failures followed by success',
                                   'score': 55, 'source': 'correlation', 'event_ids': [e['event_id'] for e in related],
                                   'host': event['host'], 'status': 'pending_review', 'requires_human_approval': False,
                                   'detection_id': str(uuid4()), 'evidence': [
                                       'At least three failures and then a success within ten minutes',
                                       f"observed period: {related[0]['timestamp']} to {event['timestamp']}",
                                       'same collector, reported host, account and source address within one batch',
                                       'Activity can be legitimate; authentication success is not proof of attack',
                                   ]})
                failures = []
    return detections
