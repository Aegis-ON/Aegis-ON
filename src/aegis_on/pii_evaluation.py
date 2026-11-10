"""Exact-span evaluation of synthetic PII annotations; independent of attack metrics."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Sequence

from .pii import PIIDetector, Span, regex_spans

COMMON_LABELS = frozenset({'EMAIL', 'TELEPHONENUM', 'IP_ADDRESS'})
NAME_LABELS = frozenset({'GIVENNAME', 'SURNAME'})
ANNOTATED_LABELS = COMMON_LABELS | NAME_LABELS


def validate_dataset(dataset: Any) -> None:
    """Check gold bounds, unique IDs, and unambiguous non-overlapping annotations."""
    if not isinstance(dataset, dict) or dataset.get('schema_version') != 1:
        raise ValueError('invalid schema_version')
    if not isinstance(dataset.get('dataset_id'), str) or not dataset['dataset_id']:
        raise ValueError('invalid dataset_id')
    labels = dataset.get('annotated_labels')
    if not isinstance(labels, list) or len(labels) != len(ANNOTATED_LABELS) or set(labels) != ANNOTATED_LABELS:
        raise ValueError('invalid annotated_labels')
    cases = dataset.get('cases')
    if not isinstance(cases, list) or not cases:
        raise ValueError('cases must be nonempty')
    ids = set()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError('invalid case')
        case_id, text, spans = case.get('case_id'), case.get('text'), case.get('spans')
        if not isinstance(case_id, str) or not case_id or case_id in ids:
            raise ValueError('invalid or duplicate case_id')
        ids.add(case_id)
        if not isinstance(text, str) or not isinstance(spans, list):
            raise ValueError('invalid text or spans')
        previous_end = 0
        for span in sorted(spans, key=lambda s: s.get('start', -1) if isinstance(s, dict) else -1):
            if not isinstance(span, dict) or span.get('label') not in ANNOTATED_LABELS:
                raise ValueError('invalid annotation')
            start, end = span.get('start'), span.get('end')
            if type(start) is not int or type(end) is not int or not (0 <= start < end <= len(text)):
                raise ValueError('invalid annotation bounds')
            if start < previous_end:
                raise ValueError('overlapping annotations')
            previous_end = end


def _metric(numerator: int, denominator: int, reason: str) -> dict[str, Any]:
    return {'value': numerator / denominator if denominator else None,
            'numerator': numerator, 'denominator': denominator,
            'undefined_reason': None if denominator else reason}


def _counts(tp: int, fp: int, fn: int, fp_ids: set[str], fn_ids: set[str]) -> dict[str, Any]:
    return {'tp': tp, 'fp': fp, 'fn': fn, 'support': tp + fn,
            'precision': _metric(tp, tp + fp, 'no predicted spans'),
            'recall': _metric(tp, tp + fn, 'no annotated spans'),
            'f1': _metric(2 * tp, 2 * tp + fp + fn, 'no annotated or predicted spans'),
            'fp_case_ids': sorted(fp_ids), 'fn_case_ids': sorted(fn_ids)}


def _score(cases: list[dict[str, Any]], predictions: dict[str, set[tuple[int, int, str]]],
           labels: frozenset[str]) -> dict[str, Any]:
    per_label: dict[str, Any] = {}
    totals = Counter()
    all_fp: set[str] = set()
    all_fn: set[str] = set()
    for label in sorted(labels):
        tp = fp = fn = 0
        fp_ids: set[str] = set()
        fn_ids: set[str] = set()
        for case in cases:
            gold = {(s['start'], s['end'], s['label']) for s in case['spans'] if s['label'] == label}
            predicted = {s for s in predictions[case['case_id']] if s[2] == label}
            tp += len(gold & predicted)
            fp += len(predicted - gold)
            fn += len(gold - predicted)
            if predicted - gold:
                fp_ids.add(case['case_id'])
            if gold - predicted:
                fn_ids.add(case['case_id'])
        per_label[label] = _counts(tp, fp, fn, fp_ids, fn_ids)
        totals.update(tp=tp, fp=fp, fn=fn)
        all_fp.update(fp_ids)
        all_fn.update(fn_ids)
    return {'labels': sorted(labels), 'overall': _counts(totals['tp'], totals['fp'], totals['fn'], all_fp, all_fn),
            'per_class': per_label}


def _normalize_predictions(spans: Iterable[Span], text: str, *, source: str | None = None) -> set[tuple[int, int, str]]:
    result = set()
    for span in spans:
        if source is not None and span.source != source:
            continue
        if (type(span.start) is not int or type(span.end) is not int
                or not 0 <= span.start < span.end <= len(text) or not isinstance(span.label, str)):
            raise ValueError('invalid predicted span')
        if span.label in ANNOTATED_LABELS:
            result.add((span.start, span.end, span.label))
    return result


def evaluate_dataset(dataset: Any, *, detector: Any | None = None,
                     dataset_sha256: str | None = None) -> dict[str, Any]:
    """Run same cases; report only counts and case IDs, never input or spans."""
    validate_dataset(dataset)
    # The manifest's IDs are untrusted input and must never appear in reports.
    # Position-based IDs let a local reader map findings back to the file.
    cases = [{**case, 'case_id': f'case-{index:04d}'}
             for index, case in enumerate(dataset['cases'], start=1)]
    if dataset_sha256 is not None and (len(dataset_sha256) != 64
            or any(c not in '0123456789abcdef' for c in dataset_sha256)):
        raise ValueError('invalid dataset digest')
    baseline = {case['case_id']: _normalize_predictions(regex_spans(case['text']), case['text']) for case in cases}
    detector = detector if detector is not None else PIIDetector.from_environment()
    model: dict[str, Any] = {'available': False, 'state': 'error', 'reason': 'detector status unavailable',
                             'common': None, 'all_annotated': None}
    try:
        state = detector.status().get('state')
        if state in ('disabled', 'error'):
            model.update(state=state, reason='model is disabled' if state == 'disabled' else 'model initialization failed')
        elif state == 'ready':
            predictions = {case['case_id']: _normalize_predictions(detector.find(case['text']), case['text'], source='model')
                           for case in cases}
            # Re-check: a backend may transition to error during inference.
            if detector.status().get('state') != 'ready':
                raise RuntimeError('model inference failed')
            model.update(available=True, state='ready', reason=None,
                         common=_score(cases, predictions, COMMON_LABELS),
                         all_annotated=_score(cases, predictions, ANNOTATED_LABELS))
    except Exception:
        # Never emit exception text: it could contain input or local paths.
        model.update(available=False, state='error', reason='model evaluation failed', common=None, all_annotated=None)
    canonical = json.dumps(dataset, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return {'schema_version': 1, 'dataset_id': 'dataset-' + hashlib.sha256(dataset['dataset_id'].encode('utf-8')).hexdigest(),
            'dataset_sha256': dataset_sha256 or hashlib.sha256(canonical).hexdigest(),
            'dataset_hash_basis': 'file bytes' if dataset_sha256 else 'canonical JSON',
            'case_count': len(cases), 'matching': 'exact start, end, and label; Unicode code-point offsets',
            'regex_baseline': {'common': _score(cases, baseline, COMMON_LABELS)}, 'model_only': model}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Evaluate synthetic PII spans locally.')
    parser.add_argument('--dataset', default='evaluation/pii_synthetic_v1.json')
    parser.add_argument('--output')
    args = parser.parse_args(argv)
    try:
        raw = Path(args.dataset).read_bytes()
        dataset = json.loads(raw.decode('utf-8-sig'))
        report = evaluate_dataset(dataset, dataset_sha256=hashlib.sha256(raw).hexdigest())
        rendered = json.dumps(report, ensure_ascii=True, indent=2, allow_nan=False) + '\n'
        if args.output:
            Path(args.output).write_text(rendered, encoding='utf-8')
        else:
            print(rendered, end='')
    except (ValueError, OSError, UnicodeDecodeError, RecursionError):
        parser.exit(2, 'PII evaluation error: invalid dataset or file access error\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
