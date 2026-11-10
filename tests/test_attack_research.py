import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from aegis_on import api
from aegis_on.attack_research import compare_commands, prepare_dev
from aegis_on.service import DetectionService


class AttackResearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dataset = json.loads(Path('evaluation/synthetic_v1.json').read_text())

    def test_dev_export_excludes_eval_unknown_and_non_commands(self):
        result = prepare_dev(self.dataset)
        by_id = {case['case_id']: case for case in self.dataset['cases']}
        self.assertEqual(len(result['examples']), 6)
        self.assertEqual(result['excluded'], {'unknown_truth': 4})
        for example in result['examples']:
            case = by_id[example['case_id']]
            self.assertEqual(case['split'], 'dev')
            self.assertEqual(case['task'], 'command_behavior')
            self.assertIn(example['label'], ('positive', 'negative'))
            self.assertTrue(example['command'].strip())

    def test_split_leaks_are_rejected_before_export(self):
        dataset = copy.deepcopy(self.dataset)
        dev = next(case for case in dataset['cases'] if case['split'] == 'dev')
        eval_case = next(case for case in dataset['cases'] if case['split'] == 'eval')
        eval_case['group_id'] = dev['group_id']
        with self.assertRaises(ValueError):
            prepare_dev(dataset)

    def test_unavailable_model_never_generates_metrics(self):
        result = compare_commands(self.dataset, split='eval', predictor=None)
        self.assertFalse(result['model_available'])
        self.assertIsNone(result['comparison'])
        self.assertEqual(result['baseline_all']['overall']['tp'], 9)

    def test_mock_comparison_same_cases_and_failures_excluded(self):
        class Fake:
            def __init__(self): self.seen = []
            def predict(self, command):
                self.seen.append(command)
                if 'calc.exe' in command: raise RuntimeError('sensitive input')
                if 'rmtree' in command: return 'abstain'
                return 'suspicious' if 'curl' in command else 'benign'
        fake = Fake()
        result = compare_commands(self.dataset, split='eval', predictor=fake)
        comparison = result['comparison']
        self.assertEqual(comparison['model']['support'], comparison['baseline']['support'])
        self.assertEqual(comparison['model']['support'], comparison['combined_or']['support'])
        self.assertEqual(result['exclusions']['model_error'], 1)
        self.assertEqual(result['exclusions']['model_abstained'], 1)
        self.assertNotIn('sensitive input', json.dumps(result))
        self.assertTrue(all(isinstance(item, str) for item in fake.seen))
        scored = [r for r in result['cases'] if r['status'] == 'evaluated']
        self.assertTrue(all(r['combined'] == (r['baseline'] or r['model']) for r in scored))

    def test_all_model_errors_are_not_reported_as_available(self):
        class Broken:
            def predict(self, command):
                raise RuntimeError(command)
        result = compare_commands(self.dataset, split='eval', predictor=Broken())
        self.assertFalse(result['model_available'])
        self.assertIsNone(result['comparison'])
        self.assertEqual(result['scored_cases'], 0)
        self.assertEqual(result['exclusions']['model_error'], 16)
        self.assertEqual(result['excluded_truth']['positive'], 10)
        self.assertEqual(result['excluded_truth']['negative'], 6)

    def test_non_string_model_outputs_are_excluded(self):
        class Invalid:
            def predict(self, command):
                # NumPy-like objects may raise when compared or coerced to bool.
                class Bad:
                    def __eq__(self, other): raise ValueError('do not compare')
                return Bad()
        result = compare_commands(self.dataset, split='eval', predictor=Invalid())
        self.assertFalse(result['model_available'])
        self.assertIsNone(result['comparison'])
        self.assertEqual(result['exclusions']['invalid_model_output'], 16)

    def test_authenticated_api_reports_unavailable_without_changing_detection(self):
        with patch.dict('os.environ', {'AEGIS_API_TOKEN': 'test-secret', 'AEGIS_ANALYST_NAME': 'analyst'}):
            api.service = DetectionService()
            with TestClient(api.app) as client:
                self.assertEqual(client.get('/api/v1/attack-model/status').status_code, 401)
                headers = {'Authorization': 'Bearer test-secret'}
                self.assertEqual(client.get('/api/v1/attack-model/status', headers=headers).json()['state'], 'unavailable')
                event = {'timestamp': '2026-11-09T10:00:00Z', 'host': 'demo', 'user': 'test',
                         'process': 'curl', 'command_line': 'curl https://example.org', 'event_id': 'evt-1'}
                response = client.post('/api/v1/analyze', headers=headers, json={'events': [event]})
                self.assertEqual(response.status_code, 200)
                result = response.json()
                self.assertEqual(result['attack_model']['state'], 'unavailable')
                self.assertTrue(any(d['source'] == 'rule' and d['event_ids'] == ['evt-1'] for d in result['detections']))
                self.assertFalse(any(d['source'] == 'attack-model' for d in result['detections']))
