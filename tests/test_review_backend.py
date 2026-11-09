import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from aegis_on import api
from aegis_on.service import DetectionService


class BackendReviewRegressions(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict('os.environ', {'AEGIS_API_TOKEN': 'test-secret', 'AEGIS_ANALYST_NAME': 'analyst-1'})
        self.env.start()
        api.service = DetectionService()
        self.client = TestClient(api.app, raise_server_exceptions=False)
        self.headers = {'Authorization': 'Bearer test-secret'}
        self.sample = json.loads(Path('data/demo_sysmon.json').read_text(encoding='utf-8'))['events']

    def tearDown(self):
        self.client.close()
        self.env.stop()

    def send(self, events):
        return self.client.post('/api/v1/sysmon/analyze', json={'events': events}, headers=self.headers)

    def test_bad_unicode_is_isolated_and_cannot_poison_stored_results(self):
        bad = copy.deepcopy(self.sample[0])
        bad['System']['Computer'] = 'host\ud800'
        bad['EventData']['CommandLine'] = 'cmd.exe /c echo hi'
        good = copy.deepcopy(self.sample[1])
        payload = json.dumps({'events': [bad, good]}, ensure_ascii=True).encode()
        response = self.client.post('/api/v1/sysmon/analyze', content=payload,
                                    headers={**self.headers, 'Content-Type': 'application/json'})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual([x['status'] for x in response.json()['items']], ['invalid', 'processed'])
        followup = self.client.get('/api/v1/detections', headers=self.headers)
        self.assertEqual(followup.status_code, 200, followup.text)

    def test_legacy_json_rejects_surrogates_before_storing_detections(self):
        event = {'timestamp': '2026-01-01T00:00:00Z', 'host': 'host\ud800',
                 'user': 'user', 'process': 'curl', 'command_line': 'curl https://example.org'}
        payload = json.dumps({'events': [event]}, ensure_ascii=True).encode()
        result = self.client.post('/api/v1/analyze', content=payload,
                                  headers={**self.headers, 'Content-Type': 'application/json'})
        self.assertEqual(result.status_code, 422)
        self.assertEqual(self.client.get('/api/v1/detections', headers=self.headers).status_code, 200)
        self.assertEqual(self.client.get('/api/v1/detections', headers=self.headers).json()['detections'], [])
        event['host'] = 'LAB-01'
        event['event_id'] = 'id\udfff'
        payload = json.dumps({'events': [event]}, ensure_ascii=True).encode()
        result = self.client.post('/api/v1/analyze', content=payload,
                                  headers={**self.headers, 'Content-Type': 'application/json'})
        self.assertEqual(result.status_code, 422)

    def test_approval_rejects_invalid_unicode_without_changing_state(self):
        event = {'timestamp': '2026-01-01T00:00:00Z', 'host': 'host',
                 'user': 'user', 'process': 'curl', 'command_line': 'curl https://example.org'}
        analysis = self.client.post('/api/v1/analyze', json={'events': [event]}, headers=self.headers)
        detection = analysis.json()['detections'][0]
        payload = json.dumps({'analyst': 'analyst-1', 'rationale': 'test\ud800'}, ensure_ascii=True).encode()
        result = self.client.post(f"/api/v1/detections/{detection['detection_id']}/approval", content=payload,
                                  headers={**self.headers, 'Content-Type': 'application/json'})
        self.assertEqual(result.status_code, 422)
        stored = self.client.get('/api/v1/detections', headers=self.headers)
        self.assertEqual(stored.status_code, 200)
        self.assertEqual(stored.json()['detections'][0]['status'], 'pending_review')

    def test_surrogates_in_other_text_fields_are_isolated(self):
        for section, field in [('EventData', 'User'), ('EventData', 'CommandLine'),
                               ('EventData', 'Image'), ('EventData', 'ParentCommandLine'),
                               ('System', 'Provider')]:
            with self.subTest(field=field):
                bad = copy.deepcopy(self.sample[0])
                bad[section][field] = 'value\udfff'
                payload = json.dumps({'events': [bad, self.sample[1]]}, ensure_ascii=True).encode()
                response = self.client.post('/api/v1/sysmon/analyze', content=payload,
                                            headers={**self.headers, 'Content-Type': 'application/json'})
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual([x['status'] for x in response.json()['items']], ['invalid', 'processed'])
        good = copy.deepcopy(self.sample[0])
        good['EventData']['CommandLine'] = 'cmd.exe /c echo \U0001f600'
        self.assertEqual(self.send([good]).json()['items'][0]['status'], 'processed')

    def test_ipv4_mapped_ipv6_is_not_a_distinct_destination(self):
        records = copy.deepcopy(self.sample[2:])
        for record, address in zip(records, ['192.0.2.1', '::ffff:192.0.2.1', '192.0.2.2']):
            record['EventData'].update(Initiated='true', DestinationIp=address)
        response = self.send(records)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(any(d['source'] == 'correlation' for d in response.json()['detections']))
        displayed = response.json()['source_events']
        self.assertEqual(displayed[0]['destination_ip'], displayed[1]['destination_ip'])
        self.assertNotIn('192.0.2.1', response.text)
        fourth = copy.deepcopy(records[-1])
        fourth['System']['EventRecordID'] = 999
        fourth['EventData']['DestinationIp'] = '192.0.2.3'
        result = self.send(records + [fourth]).json()
        self.assertEqual(len([d for d in result['detections'] if d['source'] == 'correlation']), 1)

    def test_only_explicit_outbound_connections_count_towards_fanout(self):
        records = copy.deepcopy(self.sample[2:])
        for record, initiated in zip(records, ['true', 'false', None]):
            if initiated is None:
                record['EventData'].pop('Initiated', None)
            else:
                record['EventData']['Initiated'] = initiated
        response = self.send(records)
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual([item['status'] for item in result['items']], ['processed'] * 3)
        self.assertEqual([e['initiated'] for e in result['source_events']], [True, False, None])
        self.assertFalse(any(d['source'] == 'correlation' for d in result['detections']))
        for record in records:
            record['EventData']['Initiated'] = True
        self.assertEqual(len([d for d in self.send(records).json()['detections'] if d['source'] == 'correlation']), 1)

    def test_direction_values_and_invalid_direction_are_reported(self):
        records = []
        for index, value in enumerate([True, False, 'TRUE', 'false', '', None, 'maybe', 1]):
            record = copy.deepcopy(self.sample[2])
            record['System']['EventRecordID'] = 500 + index
            record['EventData']['Initiated'] = value
            records.append(record)
        result = self.send(records).json()
        self.assertEqual([x['status'] for x in result['items']], ['processed'] * 6 + ['invalid'] * 2)
        self.assertEqual([x['initiated'] for x in result['source_events']], [True, False, True, False, None, None])


if __name__ == '__main__':
    unittest.main()
