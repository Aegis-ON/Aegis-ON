import copy
import json
from pathlib import Path
import unittest

from aegis_on.pii import PIIDetector, Span
from aegis_on.pii_evaluation import evaluate_dataset, validate_dataset

DATASET = Path(__file__).resolve().parents[1] / 'evaluation' / 'pii_synthetic_v1.json'


class FakeDetector:
    def __init__(self, predictions=None, state='ready', fail=False):
        self.predictions = predictions or {}
        self.state = state
        self.fail = fail

    def status(self):
        return {'state': self.state, 'reason': None}

    def find(self, text):
        if self.fail:
            raise RuntimeError('must not be exposed: ' + text)
        return self.predictions.get(text, [])


class PiiEvaluationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(DATASET.read_text(encoding='utf-8'))

    def test_dataset_is_valid_and_covers_expected_cases(self):
        validate_dataset(self.data)
        self.assertGreater(max(len(c['text']) for c in self.data['cases']), 5000)
        self.assertTrue(any(not c['spans'] for c in self.data['cases']))
        self.assertTrue(any(len([s for s in c['spans'] if s['label'] == 'EMAIL']) == 2 for c in self.data['cases']))
        labels = {s['label'] for c in self.data['cases'] for s in c['spans']}
        self.assertEqual(labels, {'GIVENNAME', 'SURNAME', 'EMAIL', 'TELEPHONENUM', 'IP_ADDRESS'})

    def test_exact_match_overlap_source_and_scope(self):
        text = 'test@example.test'
        case = {'case_id': 'fake-1', 'text': text,
                'spans': [{'start': 0, 'end': len(text), 'label': 'EMAIL'}]}
        dataset = {**self.data, 'cases': [case]}
        predictions = {text: [Span(0, len(text), 'EMAIL', 'model'),
                              Span(0, len(text)-1, 'EMAIL', 'model'),
                              Span(0, len(text), 'TELEPHONENUM', 'model'),
                              Span(0, len(text), 'EMAIL', 'regex'),
                              Span(0, 4, 'USERNAME', 'model')]}
        report = evaluate_dataset(dataset, detector=FakeDetector(predictions))
        score = report['model_only']['common']
        self.assertEqual((score['overall']['tp'], score['overall']['fp'], score['overall']['fn']), (1, 2, 0))
        self.assertEqual(score['per_class']['EMAIL']['fp_case_ids'], ['case-0001'])
        self.assertEqual(score['per_class']['TELEPHONENUM']['fp_case_ids'], ['case-0001'])
        self.assertIsNone(score['per_class']['IP_ADDRESS']['precision']['value'])
        self.assertIsNotNone(score['per_class']['IP_ADDRESS']['precision']['undefined_reason'])
        self.assertNotIn(text, json.dumps(report))

    def test_model_evaluated_separately_from_regex_with_core_detector(self):
        text = 'test@example.test'
        dataset = {**self.data, 'cases': [{'case_id': 'core-1', 'text': text,
                   'spans': [{'start': 0, 'end': len(text), 'label': 'EMAIL'}]}]}

        class LocalFakeModel:
            def find(self, value):
                return [Span(0, len(value), 'EMAIL', 'model'),
                        Span(0, len(value), 'EMAIL', 'model'),
                        Span(0, len(value) - 1, 'EMAIL', 'model')]

        result = evaluate_dataset(dataset, detector=PIIDetector(model=LocalFakeModel()))
        score = result['model_only']['common']['per_class']['EMAIL']
        self.assertEqual((score['tp'], score['fp'], score['fn']), (1, 1, 0))
        self.assertEqual(result['regex_baseline']['common']['overall']['tp'], 1)

    def test_disabled_and_failed_never_produce_model_scores(self):
        for detector in (FakeDetector(state='disabled'), FakeDetector(state='error'), FakeDetector(fail=True)):
            report = evaluate_dataset(self.data, detector=detector)
            self.assertFalse(report['model_only']['available'])
            self.assertIsNone(report['model_only']['common'])
            self.assertIsNone(report['model_only']['all_annotated'])
            self.assertTrue(report['model_only']['reason'])
            for case in self.data['cases']:
                self.assertNotIn(case['text'], json.dumps(report, ensure_ascii=False))

    def test_real_regex_is_deterministic_and_correct_on_clear_cases(self):
        first = evaluate_dataset(self.data, detector=FakeDetector(state='disabled'))
        second = evaluate_dataset(self.data, detector=FakeDetector(state='disabled'))
        self.assertEqual(first, second)
        labels = first['regex_baseline']['common']['per_class']
        for label in ('EMAIL', 'TELEPHONENUM', 'IP_ADDRESS'):
            self.assertGreater(labels[label]['tp'], 0)
        self.assertNotIn('case-0003', labels['EMAIL']['fn_case_ids'])
        self.assertNotIn('case-0004', labels['TELEPHONENUM']['fn_case_ids'])
        self.assertNotIn('case-0005', labels['IP_ADDRESS']['fn_case_ids'])
        self.assertNotIn('case-0008', labels['EMAIL']['fn_case_ids'])

    def test_untrusted_identifiers_cannot_leak_text(self):
        secret = 'private-person@example.test'
        dataset = {**self.data, 'dataset_id': secret, 'cases': [
            {'case_id': secret, 'text': secret,
             'spans': [{'start': 0, 'end': len(secret), 'label': 'EMAIL'}]}]}
        # A partial match produces both an FP and an FN in the report.
        detector = FakeDetector({secret: [Span(0, len(secret) - 1, 'EMAIL', 'model')]})
        report = evaluate_dataset(dataset, detector=detector)
        self.assertNotIn(secret, json.dumps(report, ensure_ascii=False))
        self.assertEqual(report['model_only']['common']['overall']['fn_case_ids'], ['case-0001'])
        self.assertEqual(report['model_only']['common']['overall']['fp_case_ids'], ['case-0001'])
        self.assertTrue(report['dataset_id'].startswith('dataset-'))
        self.assertEqual(report, evaluate_dataset(dataset, detector=detector))
        with self.assertRaises(ValueError):
            evaluate_dataset(dataset, detector=FakeDetector(), dataset_sha256=secret)

    def test_invalid_and_ambiguous_annotations_rejected(self):
        dataset = copy.deepcopy(self.data)
        start = dataset['cases'][0]['spans'][0]['start']
        dataset['cases'][0]['spans'].append({'start': start, 'end': start + 1, 'label': 'GIVENNAME'})
        with self.assertRaises(ValueError):
            validate_dataset(dataset)
        dataset = copy.deepcopy(self.data)
        dataset['cases'][0]['spans'][0]['end'] = len(dataset['cases'][0]['text']) + 1
        with self.assertRaises(ValueError):
            validate_dataset(dataset)


if __name__ == '__main__':
    unittest.main()
