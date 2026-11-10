"""Development-only command triage data preparation and comparison contract.

No trained attack model is bundled. Predictors receive only the command string;
case labels and identifiers are never passed into the predictor.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Protocol

from .evaluation import _metrics, _reject_nonfinite, _unique_json_object, evaluate_dataset, validate_dataset
from .sysmon import parse_sysmon


class CommandPredictor(Protocol):
    def predict(self, command: str) -> str:
        """Return 'suspicious', 'benign', or 'abstain'; never execute the command."""
        ...


def prepare_dev(dataset: Any) -> dict[str, Any]:
    """Produce only synthetic dev command examples, for wiring experiments.

    Not an adequate production training set. Evaluation cases are never exported.
    """
    validate_dataset(dataset)
    examples = []
    excluded: dict[str, int] = {}
    def exclude(reason: str) -> None:
        excluded[reason] = excluded.get(reason, 0) + 1
    for case in dataset['cases']:
        if case['split'] != 'dev' or case['task'] != 'command_behavior':
            continue
        if case['truth'] == 'unknown':
            exclude('unknown_truth')
            continue
        events, items = parse_sysmon({'events': case['events']})
        if len(events) != 1 or any(item['status'] != 'processed' for item in items):
            exclude('invalid_or_unsupported')
            continue
        event = events[0]
        if event['source_metadata']['sysmon_event_id'] != 1:
            exclude('wrong_event_type')
            continue
        command = event['command_line']
        if not command.strip():
            exclude('missing_command')
            continue
        examples.append({'case_id': case['case_id'], 'group_id': case['group_id'],
                         'command': command, 'label': case['truth']})
    return {'dataset_id': dataset['dataset_id'], 'split': 'dev',
            'purpose': 'synthetic wiring only; not representative training data',
            'examples': examples, 'excluded': excluded}


def compare_commands(dataset: Any, *, split: str, predictor: CommandPredictor | None) -> dict[str, Any]:
    """Compare on the exact same eligible event cases, excluding abstentions.

    A missing/failing predictor is never interpreted as a negative prediction.
    No correlation or ATT&CK scores are produced here.
    """
    baseline = evaluate_dataset(dataset, split=split)
    if predictor is None:
        return {'split': split, 'model_available': False, 'reason': 'no verified attack model',
                'baseline_all': baseline['tasks']['command_behavior'], 'comparison': None}
    by_id = {case['case_id']: case for case in dataset['cases']}
    baseline_records, model_records, combined_records = [], [], []
    exclusions: dict[str, int] = {}
    excluded_truth: dict[str, int] = {}
    rows = []
    for row in baseline['cases']:
        if row['task'] != 'command_behavior':
            continue
        reason = None
        if row['status'] != 'evaluated':
            reason = row['status']
        else:
            events, _ = parse_sysmon({'events': by_id[row['case_id']]['events']})
            command = events[0]['command_line']
            if not command.strip():
                reason = 'missing_command'
            else:
                try:
                    prediction = predictor.predict(command)
                except Exception:
                    # Never expose an exception or the command in a report.
                    reason = 'model_error'
                else:
                    if type(prediction) is not str:
                        reason = 'invalid_model_output'
                    elif prediction == 'abstain':
                        reason = 'model_abstained'
                    elif prediction not in ('suspicious', 'benign'):
                        reason = 'invalid_model_output'
        if reason:
            exclusions[reason] = exclusions.get(reason, 0) + 1
            if row['truth'] in ('positive', 'negative'):
                excluded_truth[row['truth']] = excluded_truth.get(row['truth'], 0) + 1
            rows.append({'case_id': row['case_id'], 'status': reason})
            continue
        truth = row['truth'] == 'positive'
        base = row['predicted_positive']
        model = prediction == 'suspicious'
        case_id = row['case_id']
        baseline_records.append((case_id, truth, base))
        model_records.append((case_id, truth, model))
        combined_records.append((case_id, truth, base or model))
        rows.append({'case_id': case_id, 'status': 'evaluated', 'baseline': base,
                     'model': model, 'combined': base or model})
    comparison = ({'baseline': _metrics(baseline_records), 'model': _metrics(model_records),
                   'combined_or': _metrics(combined_records)} if model_records else None)
    return {'split': split, 'model_available': bool(model_records), 'exclusions': exclusions,
            'excluded_truth': excluded_truth, 'scored_cases': len(model_records), 'cases': rows,
            'baseline_all': baseline['tasks']['command_behavior'], 'comparison': comparison,
            'note': 'Combined OR is an evaluation experiment, not a product integration.'}


def main() -> int:
    parser = argparse.ArgumentParser(description='Prepare synthetic dev-only command examples for wiring checks.')
    parser.add_argument('--dataset', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        raw = Path(args.dataset).read_bytes()
        if Path(args.dataset).resolve() == Path(args.output).resolve():
            raise ValueError('output must differ from input')
        dataset = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_unique_json_object,
                             parse_constant=_reject_nonfinite)
        result = prepare_dev(dataset)
        result['input_sha256'] = hashlib.sha256(raw).hexdigest()
        Path(args.output).write_text(json.dumps(result, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    except (OSError, ValueError, UnicodeDecodeError, RecursionError):
        parser.exit(2, 'Unable to prepare dataset; check the dataset and output path.\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
