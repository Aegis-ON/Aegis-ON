import json
import re
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from aegis_on import api
from aegis_on.pii import PIIDetector, Span
from aegis_on.service import DetectionService


class SyntheticModel:
    def find(self, text):
        return [Span(m.start(), m.end(), 'GIVENNAME', 'model') for m in re.finditer('JaneDoe', text)]


class BrokenModel:
    def find(self, text):
        raise ValueError('JaneDoe secret and private path')


class UUIDModel:
    def find(self, text):
        pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        return [Span(m.start(), m.end(), 'IDCARD', 'model') for m in re.finditer(pattern, text)]


class PiiApiTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict('os.environ', {'AEGIS_API_TOKEN': 'test-token', 'AEGIS_ANALYST_NAME': 'analyst'}, clear=False)
        self.env.start()
        self.old_service, self.old_detector = api.service, api.pii_detector
        api.service, api.pii_detector = DetectionService(), PIIDetector()
        self.client = TestClient(api.app)
        self.headers = {'Authorization': 'Bearer test-token'}

    def tearDown(self):
        self.client.close()
        api.service, api.pii_detector = self.old_service, self.old_detector
        self.env.stop()

    @staticmethod
    def event():
        return {'timestamp': '2026-01-01T00:00:00Z', 'host': 'JaneDoe-laptop', 'user': 'JaneDoe',
                'process': 'JaneDoe.exe', 'event_id': 'JaneDoe-record',
                'command_line': 'curl https://example.org/JaneDoe'}

    def test_status_is_authenticated_and_disabled_still_reports_regex(self):
        self.assertEqual(self.client.get('/api/v1/pii/status').status_code, 401)
        self.assertEqual(self.client.get('/api/v1/pii/status', headers=self.headers).json()['state'], 'disabled')
        event = self.event()
        event['command_line'] = 'curl analyst@example.test'
        response = self.client.post('/api/v1/analyze', json={'events': [event]}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        pii = response.json()['pii']
        self.assertEqual(pii['state'], 'disabled')
        self.assertTrue(any(x['type'] == 'EMAIL' and x['source'] == 'regex' for x in pii['findings']))
        self.assertNotIn('analyst@example.test', response.text)
        self.assertTrue(all(x['event_id'] == response.json()['event_refs'][0]['event_id'] for x in pii['findings']))

    def test_model_candidates_redacted_from_responses_and_stored_detections(self):
        api.pii_detector = PIIDetector(SyntheticModel())
        response = self.client.post('/api/v1/analyze', json={'events': [self.event()]}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('JaneDoe', response.text)
        data = response.json()
        self.assertEqual(data['pii']['state'], 'ready')
        self.assertTrue(any(item['source'] == 'model' for item in data['pii']['findings']))
        self.assertEqual(data['detections'][0]['event_ids'][0], data['event_refs'][0]['event_id'])
        listing = self.client.get('/api/v1/detections', headers=self.headers)
        self.assertNotIn('JaneDoe', listing.text)
        detection_id = data['detections'][0]['detection_id']
        approval = self.client.post('/api/v1/detections/' + detection_id + '/approval', headers=self.headers,
                                    json={'analyst': 'analyst', 'rationale': 'JaneDoe approved'})
        self.assertEqual(approval.status_code, 200)
        self.assertNotIn('JaneDoe', approval.text)

    def test_sysmon_candidates_link_to_processed_input(self):
        api.pii_detector = PIIDetector(SyntheticModel())
        event = {'System': {'Provider': 'Microsoft-Windows-Sysmon', 'EventID': 1,
                            'TimeCreated': '2026-01-01T00:00:00Z', 'Computer': 'JaneDoe-PC',
                            'Channel': 'Microsoft-Windows-Sysmon/Operational'},
                 'EventData': {'Image': r'C:\Users\JaneDoe\curl.exe', 'User': 'JaneDoe',
                               'CommandLine': 'curl https://example.org/JaneDoe'}}
        result = self.client.post('/api/v1/sysmon/analyze', json={'events': [event]}, headers=self.headers)
        self.assertEqual(result.status_code, 200)
        self.assertNotIn('JaneDoe', result.text)
        payload = result.json()
        self.assertTrue(payload['pii']['findings'])
        self.assertTrue(all(x['input_index'] == 0 and x['event_id'] == payload['source_events'][0]['event_id']
                            for x in payload['pii']['findings']))

    def test_sysmon_id_pseudonym_is_consistent_across_all_response_links(self):
        api.pii_detector = PIIDetector(UUIDModel())
        with open('data/demo_sysmon.json', encoding='utf-8') as handle:
            result = self.client.post('/api/v1/sysmon/analyze', json=json.load(handle), headers=self.headers)
        self.assertEqual(result.status_code, 200)
        payload = result.json()
        source_ids = {item['event_id'] for item in payload['source_events']}
        self.assertEqual(source_ids, {item['event_id'] for item in payload['items'] if item['status'] == 'processed'})
        self.assertTrue(all(set(d['event_ids']) <= source_ids for d in payload['detections']))
        self.assertTrue(all(f['event_id'] in source_ids for f in payload['pii']['findings']))

    def test_inference_failure_fails_before_detection_storage(self):
        api.pii_detector = PIIDetector(BrokenModel())
        response = self.client.post('/api/v1/analyze', json={'events': [self.event()]}, headers=self.headers)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn('JaneDoe', response.text)
        self.assertEqual(api.service.list_detections(), [])
        self.assertEqual(self.client.get('/api/v1/pii/status', headers=self.headers).json()['state'], 'error')

    def test_invalid_input_and_validation_errors_do_not_echo_secrets(self):
        event = self.event()
        event['timestamp'] = 'secret-JaneDoe'
        response = self.client.post('/api/v1/analyze', json={'events': [event]}, headers=self.headers)
        self.assertEqual(response.status_code, 422)
        self.assertNotIn('secret-JaneDoe', response.text)

    def test_non_string_text_fields_cannot_bypass_candidate_scanning(self):
        api.pii_detector = PIIDetector(SyntheticModel())
        event = self.event()
        event['host'] = ['JaneDoe']
        response = self.client.post('/api/v1/analyze', json={'events': [event]}, headers=self.headers)
        self.assertEqual(response.status_code, 422)
        self.assertNotIn('JaneDoe', response.text)
        self.assertEqual(api.service.list_detections(), [])
        response = self.client.post('/api/v1/analyze', json={'events': ['secret-JaneDoe']}, headers=self.headers)
        self.assertEqual(response.status_code, 422)
        self.assertNotIn('secret-JaneDoe', response.text)

    def test_model_size_limit_precedes_storage(self):
        api.pii_detector = PIIDetector(SyntheticModel())
        event = self.event()
        event['command_line'] = 'x' * 250_001
        response = self.client.post('/api/v1/analyze', json={'events': [event]}, headers=self.headers)
        self.assertEqual(response.status_code, 413)
        self.assertEqual(api.service.list_detections(), [])


if __name__ == '__main__':
    unittest.main()
