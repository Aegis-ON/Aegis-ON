"""Validate the fixed synthetic benchmark and its independently stated labels."""
import hashlib
import ipaddress
import json
import unittest
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from aegis_on.evaluation import evaluate_dataset
from aegis_on.sysmon import parse_sysmon

DATASET = Path('evaluation/synthetic_v1.json')
TRUTHS = {'positive', 'negative', 'unknown'}
TECHNIQUES = {'T1105', 'T1485', 'T1489', 'T1059'}


def destination_key(value):
    address = ipaddress.ip_address(value)
    return str(address.ipv4_mapped or address) if isinstance(address, ipaddress.IPv6Address) else str(address)


def observed_fanout(events):
    """Independent inclusive time-window oracle, scoped to each source host."""
    by_host = defaultdict(list)
    for event in events:
        if event['source_metadata']['initiated'] is True:
            by_host[event['host'].casefold()].append(event)
    for outgoing in by_host.values():
        outgoing.sort(key=lambda e: e['timestamp'])
        times = [datetime.fromisoformat(e['timestamp']) for e in outgoing]
        if any(len({destination_key(outgoing[j]['destination']) for j in range(len(outgoing))
                    if times[i] <= times[j] <= times[i] + timedelta(minutes=10)}) >= 3
               for i in range(len(outgoing))):
            return True
    return False


class EvaluationDatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dataset = json.loads(DATASET.read_text(encoding='utf-8'))
        cls.cases = cls.dataset['cases']

    def test_manifest_shape_and_bounded_inputs(self):
        self.assertEqual(self.dataset['schema_version'], 1)
        self.assertEqual(self.dataset['dataset_id'], 'aegis-synthetic-v1')
        self.assertEqual(len(self.cases), 43)
        seen = set()
        for case in self.cases:
            with self.subTest(case=case.get('case_id')):
                self.assertTrue(case['case_id'] and case['group_id'])
                self.assertNotIn(case['case_id'], seen)
                seen.add(case['case_id'])
                self.assertIn(case['split'], {'dev', 'eval'})
                self.assertIn(case['truth'], TRUTHS)
                self.assertIn(case['context'], {'benign', 'suspicious', 'unknown'})
                self.assertIs(case['synthetic'], True)
                self.assertTrue(case['truth_reason'].strip())
                self.assertTrue(case['expected_engine_behavior'].strip())
                self.assertTrue(set(case['technique_truth']) <= TECHNIQUES)
                self.assertTrue(all(v in TRUTHS for v in case['technique_truth'].values()))
                self.assertTrue(1 <= len(case['events']) <= 1000)
                if case['task'] == 'command_behavior':
                    self.assertEqual(case['unit'], 'event')
                    self.assertEqual(len(case['events']), 1)
                else:
                    self.assertEqual((case['task'], case['unit']), ('fanout_condition', 'batch'))
                    self.assertFalse(case['technique_truth'], 'fan-out is not ground truth for ATT&CK T1595')

    def test_group_and_exact_input_disjointness_across_splits(self):
        splits_by_group = defaultdict(set)
        splits_by_command = defaultdict(set)
        splits_by_input = defaultdict(set)
        for case in self.cases:
            splits_by_group[case['group_id']].add(case['split'])
            for event in case['events']:
                command = event.get('EventData', {}).get('CommandLine', '')
                if command:
                    splits_by_command[' '.join(command.casefold().split())].add(case['split'])
                # Canonical input digest catches identical records with arbitrary JSON key order.
                record = json.dumps(event, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
                splits_by_input[hashlib.sha256(record).hexdigest()].add(case['split'])
        for label, groups in [('group', splits_by_group), ('command', splits_by_command), ('input hash', splits_by_input)]:
            for key, splits in groups.items():
                with self.subTest(category=label, key=key):
                    self.assertLessEqual(len(splits), 1)

    def test_related_scenario_variants_share_group_and_split(self):
        by_id = {case['case_id']: case for case in self.cases}
        families = [
            ('eval-curl-tool', 'eval-curl-maint', 'eval-wget-tool', 'eval-wget-info'),
            ('eval-sc-stop', 'eval-sc-query', 'eval-stop-service', 'eval-service-get'),
            ('eval-normal-three', 'eval-suspicious-three'),
            ('dev-exact-boundary', 'dev-outside-boundary'),
        ]
        for family in families:
            with self.subTest(family=family):
                self.assertEqual(len({by_id[case_id]['group_id'] for case_id in family}), 1)
                self.assertEqual(len({by_id[case_id]['split'] for case_id in family}), 1)

    def test_documented_rejects_and_labeled_balance(self):
        by_id = {case['case_id']: case for case in self.cases}
        expected = {'dev-invalid-image': 'invalid', 'eval-invalid-time': 'invalid',
                    'eval-unsupported': 'unsupported', 'eval-partial-batch': 'invalid'}
        for case in self.cases:
            with self.subTest(case=case['case_id']):
                _, items = parse_sysmon({'events': case['events']})
                errors = [item['status'] for item in items if item['status'] != 'processed']
                if case['case_id'] in expected:
                    self.assertIn(expected[case['case_id']], errors)
                    self.assertEqual(case['truth'], 'unknown')
                else:
                    self.assertEqual(errors, [])
        counts = Counter((c['split'], c['task'], c['truth']) for c in self.cases)
        for split in ('dev', 'eval'):
            for task in ('command_behavior', 'fanout_condition'):
                for truth in TRUTHS:
                    self.assertGreater(counts[split, task, truth], 0, (split, task, truth))
        self.assertEqual(by_id['dev-empty-command']['truth'], 'unknown')
        self.assertEqual(by_id['dev-empty-command']['technique_truth']['T1059'], 'positive')
        self.assertEqual(by_id['dev-cert-hash']['technique_truth']['T1105'], 'negative')
        self.assertEqual(by_id['eval-rmdir']['technique_truth']['T1485'], 'positive')
        self.assertEqual(by_id['eval-python-rmtree']['truth'], 'positive')
        self.assertEqual(by_id['eval-python-rmtree']['technique_truth']['T1485'], 'positive')

    def test_known_fanout_labels_follow_declared_condition(self):
        for case in self.cases:
            if case['task'] != 'fanout_condition' or case['truth'] == 'unknown':
                continue
            with self.subTest(case=case['case_id']):
                events, items = parse_sysmon({'events': case['events']})
                self.assertTrue(all(i['status'] == 'processed' for i in items))
                self.assertTrue(all(e['source_metadata']['initiated'] in (True, False) for e in events))
                qualifies = observed_fanout(events)
                self.assertEqual(qualifies, case['truth'] == 'positive')

    def test_fanout_oracle_does_not_combine_hosts(self):
        case = next(c for c in self.cases if c['case_id'] == 'eval-suspicious-three')
        events, _ = parse_sysmon({'events': case['events']})
        self.assertTrue(observed_fanout(events))
        events[2]['host'] = 'SECOND-HOST'
        self.assertFalse(observed_fanout(events))
        events[2]['host'] = events[0]['host'].lower()
        self.assertTrue(observed_fanout(events))

    def test_missing_command_keeps_observed_interpreter_and_exposes_miss(self):
        report = evaluate_dataset(self.dataset, split='dev')
        row = next(row for row in report['cases'] if row['case_id'] == 'dev-empty-command')
        self.assertEqual(row['status'], 'excluded_unknown_truth')
        self.assertEqual(row['technique_truth']['T1059'], 'positive')
        self.assertIn('dev-empty-command', report['techniques']['T1059']['overall']['case_ids']['fn'])

    def test_report_distinguishes_triage_errors_from_technique_misses(self):
        report = evaluate_dataset(self.dataset, split='eval')
        triage = report['tasks']['command_behavior']['overall']['case_ids']
        self.assertIn('eval-service-get', triage['fp'])
        self.assertIn('eval-wget-info', triage['fp'])
        self.assertIn('eval-python-rmtree', triage['fn'])
        self.assertIn('eval-rmdir', triage['tp'])
        destructive = report['techniques']['T1485']['overall']['case_ids']['fn']
        self.assertIn('eval-rmdir', destructive)
        self.assertIn('eval-python-rmtree', destructive)
        row = next(row for row in report['cases'] if row['case_id'] == 'eval-rmdir')
        self.assertTrue(any(prediction['technique'] == 'T1059' for prediction in row['predictions']))
        self.assertFalse(any(prediction['technique'] == 'T1485' for prediction in row['predictions']))

    def test_synthetic_reserved_network_addresses(self):
        allowed = [ipaddress.ip_network('192.0.2.0/24'), ipaddress.ip_network('198.51.100.0/24'),
                   ipaddress.ip_network('203.0.113.0/24'), ipaddress.ip_network('2001:db8::/32')]
        for case in self.cases:
            for event in case['events']:
                for field in ('SourceIp', 'DestinationIp'):
                    address = event.get('EventData', {}).get(field)
                    if not address or address == 'invalid-ip':
                        continue
                    parsed = ipaddress.ip_address(address)
                    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
                        parsed = parsed.ipv4_mapped
                    with self.subTest(case=case['case_id'], field=field):
                        self.assertTrue(any(parsed.version == network.version and parsed in network for network in allowed))


if __name__ == '__main__':
    unittest.main()
