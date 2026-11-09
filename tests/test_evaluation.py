import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from aegis_on.evaluation import AegisAdapter, Prediction, evaluate_dataset, validate_dataset


def event(command, *, record=1, destination=None, minute=0):
    network = destination is not None
    data = {'UtcTime': f'2026-11-09 10:{minute:02}:00.000',
            'Image': r'C:\Windows\System32\notepad.exe', 'CommandLine': command}
    if network:
        data.update(DestinationIp=destination, Initiated='true')
    return {'System': {'Provider': 'Microsoft-Windows-Sysmon', 'EventID': 3 if network else 1,
                       'TimeCreated': f'2026-11-09T10:{minute:02}:00Z', 'Computer': 'LAB-01',
                       'EventRecordID': record, 'Channel': 'Microsoft-Windows-Sysmon/Operational'},
            'EventData': data}


def case(case_id, truth, command, *, split='eval', context='benign', technique_truth=None):
    return {'case_id': case_id, 'group_id': 'group-' + case_id, 'split': split, 'unit': 'event',
            'task': 'command_behavior', 'truth': truth, 'truth_reason': 'independent synthetic annotation',
            'context': context, 'expected_engine_behavior': 'exercise input',
            'technique_truth': technique_truth or {}, 'synthetic': True,
            'events': [event(command)]}


def dataset(*cases):
    return {'schema_version': 1, 'dataset_id': 'unit-test-dataset', 'cases': list(cases)}


class ToyAdapter:
    name = 'independent-model'
    command_sources = ('independent-model',)
    fanout_sources = ('independent-model',)

    def predict(self, events, task):
        assert task in ('command_behavior', 'fanout_condition')
        assert all(not hasattr(e, 'truth') and not hasattr(e, 'case_id') for e in events)
        assert all('truth' not in e.source_metadata for e in events)
        assert all(e.event_id.startswith('evt-') and len(e.event_id) == 68 for e in events)
        assert all('positive' not in e.event_id and 'suspicious' not in e.event_id for e in events)
        if any('alert' in e.command_line.lower() for e in events):
            # Duplicate detections must still count only one case/technique.
            p = Prediction('T1059', self.name, (events[0].event_id,), .9, ('synthetic signal',))
            return [p, p]
        return []


class EvaluationTests(unittest.TestCase):
    def test_confusion_sources_context_and_dedup(self):
        cases = dataset(case('tp', 'positive', 'alert true', context='suspicious', technique_truth={'T1059':'positive'}),
                        case('fp', 'negative', 'alert false', technique_truth={'T1059':'negative'}),
                        case('tn', 'negative', 'nothing here', technique_truth={'T1059':'negative'}),
                        case('fn', 'positive', 'not triggered', context='suspicious', technique_truth={'T1059':'positive'}),
                        case('skip', 'unknown', 'alert unknown', technique_truth={'T1059':'unknown'}))
        report = evaluate_dataset(cases, split='eval', adapter=ToyAdapter())
        task = report['tasks']['command_behavior']
        self.assertEqual([task['overall'][k] for k in ('tp','fp','tn','fn')], [1,1,1,1])
        self.assertEqual(task['overall']['precision']['value'], .5)
        self.assertEqual(task['overall']['precision']['denominator'], 2)
        self.assertEqual(task['overall']['recall']['value'], .5)
        self.assertEqual(task['overall']['f1']['value'], .5)
        self.assertEqual(task['excluded_unknown_truth'], 1)
        self.assertEqual(task['overall']['case_ids']['fp'], ['fp'])
        self.assertEqual(task['overall']['case_ids']['fn'], ['fn'])
        self.assertEqual(task['by_source']['independent-model']['tp'], 1)
        self.assertEqual(report['techniques']['T1059']['overall']['support'], 4)
        self.assertEqual(task['benign_context_alerts'][0]['case_id'], 'fp')
        self.assertEqual(len(next(c for c in report['cases'] if c['case_id'] == 'tp')['predictions']), 2)

    def test_unknown_task_truth_does_not_exclude_known_technique_truth(self):
        report = evaluate_dataset(dataset(case('unknown', 'unknown', 'alert sample',
                                               technique_truth={'T1059':'positive'})),
                                  split='eval', adapter=ToyAdapter())
        self.assertEqual(report['tasks']['command_behavior']['overall']['support'], 0)
        self.assertEqual(report['tasks']['command_behavior']['excluded_unknown_truth'], 1)
        self.assertEqual(report['techniques']['T1059']['overall']['tp'], 1)
        self.assertEqual(report['techniques']['T1059']['overall']['support'], 1)
        self.assertEqual(report['techniques']['T1105']['excluded_unannotated'], 1)
        self.assertIn('not establish malicious', report['interpretation']['techniques'])

    def test_zero_denominators_are_null_with_reason(self):
        report = evaluate_dataset(dataset(case('negative', 'negative', 'notepad')), split='eval', adapter=ToyAdapter())
        metrics = report['tasks']['command_behavior']['overall']
        self.assertEqual(metrics['tn'], 1)
        for name in ('precision','recall','f1'):
            self.assertIsNone(metrics[name]['value'])
            self.assertEqual(metrics[name]['denominator'], 0)
            self.assertTrue(metrics[name]['undefined_reason'])

    def test_invalid_or_unsupported_records_exclude_whole_case(self):
        bad = case('bad', 'positive', 'alert')
        bad['events'][0]['EventData']['Image'] = ''
        unsupported = case('unsupported', 'positive', 'another alert')
        unsupported['events'][0]['System']['EventID'] = 22
        report = evaluate_dataset(dataset(bad, unsupported, case('ok','negative','ok')),
                                  split='eval', adapter=ToyAdapter())
        self.assertEqual(report['tasks']['command_behavior']['excluded_invalid_input'], 2)
        self.assertEqual(report['tasks']['command_behavior']['overall']['support'], 1)
        self.assertEqual(report['tasks']['command_behavior']['overall']['fn'], 0)
        self.assertEqual([c['input_errors'][0]['status'] for c in report['cases'] if c['input_errors']], ['invalid','unsupported'])

    def test_real_engine_cases_and_benign_fanout(self):
        benign = case('benign-rule-fp', 'negative', 'certutil -hashfile report.pdf SHA256',
                      technique_truth={'T1105':'negative'})
        missed = case('destruction-fn', 'positive', r'rmdir /s /q C:\temp',
                      context='suspicious', technique_truth={'T1485':'positive'})
        batch = {'case_id':'benign-fanout', 'group_id':'group-fanout', 'split':'eval', 'unit':'batch',
                 'task':'fanout_condition', 'truth':'positive', 'truth_reason':'three outgoing destinations',
                 'context':'benign', 'expected_engine_behavior':'one fanout alert', 'technique_truth':{},
                 'synthetic':True, 'events':[event('',record=i+1,destination=f'192.0.2.{i+1}',minute=i) for i in range(3)]}
        report = evaluate_dataset(dataset(benign, missed, batch), split='eval')
        self.assertEqual(report['tasks']['command_behavior']['overall']['fp'], 1)
        self.assertEqual(report['tasks']['command_behavior']['overall']['fn'], 1)
        fanout = report['tasks']['fanout_condition']
        self.assertEqual((fanout['overall']['tp'], fanout['overall']['fp']), (1,0))
        self.assertEqual(fanout['benign_context_alerts'][0]['case_id'], 'benign-fanout')
        self.assertEqual(report['techniques']['T1105']['by_source']['rule']['fp'], 1)
        self.assertEqual(report['techniques']['T1485']['overall']['fn'], 1)
        row = next(c for c in report['cases'] if c['case_id']=='benign-fanout')
        prediction = row['predictions'][0]
        self.assertEqual(prediction['event_ids'], [ref['event_id'] for ref in row['input_event_refs']])
        self.assertEqual([ref['input_index'] for ref in row['input_event_refs']], [0,1,2])

    def test_cross_split_leakage_and_schema_rejected(self):
        first = case('train','positive','one distinct command',split='dev')
        second = case('test','negative','another command',split='eval')
        bad_group = copy.deepcopy(second); bad_group['group_id'] = first['group_id']
        with self.assertRaisesRegex(ValueError, 'group_id'): validate_dataset(dataset(first,bad_group))
        bad_event = copy.deepcopy(second); bad_event['events'] = copy.deepcopy(first['events'])
        with self.assertRaisesRegex(ValueError, 'input event'): validate_dataset(dataset(first,bad_event))
        bad_command = copy.deepcopy(second); bad_command['events'][0]['EventData']['CommandLine'] = '  ONE   DISTINCT COMMAND '
        with self.assertRaisesRegex(ValueError, 'normalized command'): validate_dataset(dataset(first,bad_command))
        bad_schema = copy.deepcopy(second); bad_schema['technique_truth']={'T1595':'positive'}
        with self.assertRaisesRegex(ValueError, 'technique_truth'): validate_dataset(dataset(first,bad_schema))
        bad_unit = copy.deepcopy(second); bad_unit['events'].append(event('other',record=2))
        with self.assertRaisesRegex(ValueError, 'exactly one'): validate_dataset(dataset(first,bad_unit))

    def test_deterministic_output_and_cli_file_hash(self):
        ds = dataset(case('definitely-suspicious-positive','positive','curl https://example.org'))
        first = evaluate_dataset(ds, split='eval')
        self.assertEqual(first, evaluate_dataset(ds, split='eval'))
        reference = first['cases'][0]['input_event_refs'][0]
        self.assertEqual(reference['input_index'], 0)
        self.assertNotIn('suspicious', reference['event_id'])
        self.assertNotIn('positive', reference['event_id'])
        relabeled = copy.deepcopy(ds)
        relabeled['cases'][0].update(case_id='different-id', truth='negative', context='benign')
        relabeled['cases'][0]['events'][0]['EventData']['ignored_label'] = 'positive'
        other = evaluate_dataset(relabeled, split='eval')
        self.assertEqual(reference, other['cases'][0]['input_event_refs'][0])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'data.json'; output = Path(directory)/'report.json'
            data = json.dumps(ds).encode(); path.write_bytes(data)
            result = subprocess.run([sys.executable, '-m', 'aegis_on.evaluation', '--dataset', str(path),
                                     '--split', 'eval', '--output', str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(output.read_text())
            self.assertEqual(report['dataset_sha256'], hashlib.sha256(data).hexdigest())
            self.assertEqual(report['dataset_hash_basis'], 'file bytes')
            path.write_text('{"schema_version":1,"schema_version":1}', encoding='utf-8')
            result = subprocess.run([sys.executable, '-m', 'aegis_on.evaluation', '--dataset', str(path),
                                     '--split', 'eval'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('duplicate JSON key', result.stderr)


if __name__ == '__main__':
    unittest.main()
