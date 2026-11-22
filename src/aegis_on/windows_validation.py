"""Local-only comparison of two command models on one Sysmon JSON batch.

No input content, machine names, IPs, file paths or record identifiers are
included in the result. Input indexes let an operator inspect the local file.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from .attack_model import AttackModel
from .engine import RuleDetector, SemanticRiskAdapter
from .models import SecurityEvent
from .sysmon import parse_sysmon

MAX_BYTES = 2 * 1024 * 1024
ORIGINAL = 'c33ad158789d3b57d60947ac89346ade3eec16c0045b381356fed423c025bf28'
REFINED = 'bff7da13980f8c939c63d102c33a7143e90e3113182b9ebdc9116889255d0432'


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError('non-finite JSON value')


def decode_payload(raw: bytes) -> Any:
    if len(raw) > MAX_BYTES:
        raise ValueError('input exceeds 2 MiB')
    return json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_unique_object,
                      parse_constant=_reject_nonfinite)


def load_model(directory: str, manifest: str, expected: str) -> AttackModel:
    if not directory or not manifest:
        raise ValueError('both local model directory and trusted manifest are required')
    old = {k: os.environ.get(k) for k in ('AEGIS_ATTACK_MODEL_DIR', 'AEGIS_ATTACK_MODEL_MANIFEST')}
    try:
        os.environ['AEGIS_ATTACK_MODEL_DIR'] = directory
        os.environ['AEGIS_ATTACK_MODEL_MANIFEST'] = manifest
        model = AttackModel.from_environment()
    finally:
        for key, value in old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    if model.state != 'ready' or model.version != expected:
        raise ValueError('model unavailable or artifact identity mismatch')
    return model


def compare(payload: Any, original: Any, refined: Any, source: str) -> dict[str, Any]:
    if source not in ('local-normal', 'synthetic'):
        raise ValueError('invalid source selection')
    normalized, items = parse_sysmon(payload)
    events = {event['event_id']: SecurityEvent.from_mapping(event, allow_empty_command_line=True)
              for event in normalized}
    counts = Counter(item['status'] for item in items)
    rows = []
    method_counts = {name: Counter({'eligible': 0, 'flagged': 0}) for name in ('rule', 'keyword', 'baseline', 'original', 'refined')}
    paired = Counter({'events': 0, 'rule': 0, 'keyword': 0, 'baseline': 0, 'original': 0, 'refined': 0})
    rule = RuleDetector()
    keyword = SemanticRiskAdapter()
    for item in items:
        if item['status'] != 'processed':
            # No arbitrary parser error or input data is returned.
            rows.append({'input_index': item['input_index'], 'status': item['status']})
            continue
        event = events[item['event_id']]
        flags = {'rule': bool(rule.detect(event)), 'keyword': bool(keyword.classify(event))}
        flags['baseline'] = flags['rule'] or flags['keyword']
        for name, flagged in flags.items():
            method_counts[name]['eligible'] += 1
            method_counts[name]['flagged'] += int(flagged)
        for name, predictor in (('original', original), ('refined', refined)):
            result = predictor.predict(event.command_line)
            status = result.get('status') if isinstance(result, dict) else 'invalid_output'
            if status == 'ok' and result.get('label') in ('review', 'below_threshold'):
                flags[name] = result['label'] == 'review'
                method_counts[name]['eligible'] += 1
                method_counts[name]['flagged'] += int(flags[name])
            else:
                # Whitelist statuses to avoid accidentally exposing exception text.
                allowed = {'missing_command', 'invalid_input', 'too_long', 'model_unavailable', 'inference_error'}
                status = status if status in allowed else 'invalid_output'
                flags[name] = None
                method_counts[name][status] += 1
        if event.source_metadata['sysmon_event_id'] == 1 and flags['original'] is not None and flags['refined'] is not None:
            paired['events'] += 1
            for name in ('rule', 'keyword', 'baseline', 'original', 'refined'):
                paired[name] += int(flags[name])
        rows.append({'input_index': item['input_index'], 'status': 'processed',
                     'sysmon_event_id': event.source_metadata['sysmon_event_id'], 'flags': flags})
    return {'source_declared_by_operator': source, 'input_events': len(items),
            'processed': counts['processed'], 'invalid': counts['invalid'], 'unsupported': counts['unsupported'],
            'methods': {name: dict(c) for name, c in method_counts.items()},
            'paired_event1': dict(paired),
            'cases': rows,
            'limitations': ['source is operator-declared', 'counts are event-level review signals, not attacks',
                            'rule and keyword may overlap; correlation is not included',
                            'model inputs without commands or above limits are excluded',
                            'no recall or attack rate can be inferred from normal logs']}


def main() -> int:
    parser = argparse.ArgumentParser(description='Local-only Sysmon comparison; prints no raw event fields')
    parser.add_argument('--input', required=True)
    parser.add_argument('--source', required=True, choices=('local-normal', 'synthetic'))
    parser.add_argument('--original-dir', required=True)
    parser.add_argument('--original-manifest', required=True)
    parser.add_argument('--refined-dir', required=True)
    parser.add_argument('--refined-manifest', required=True)
    args = parser.parse_args()
    try:
        with Path(args.input).open('rb') as handle:
            raw = handle.read(MAX_BYTES + 1)
        payload = decode_payload(raw)
        original = load_model(args.original_dir, args.original_manifest, ORIGINAL)
        refined = load_model(args.refined_dir, args.refined_manifest, REFINED)
        result = compare(payload, original, refined, args.source)
    except (OSError, ValueError, UnicodeError, RecursionError):
        # Never echo a file path, exception, input content, or credentials.
        print('Validation failed: check input, size and model/manifest configuration.', file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
