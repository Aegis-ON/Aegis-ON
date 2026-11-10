import unittest
from pathlib import Path
from tempfile import NamedTemporaryFile
from unittest.mock import patch

from fastapi.testclient import TestClient

from aegis_on import api
from aegis_on.service import DetectionService


class ApiRegressionTests(unittest.TestCase):
    def setUp(self):
        self.config = patch.dict('os.environ', {'AEGIS_API_TOKEN': 'test-secret', 'AEGIS_ANALYST_NAME': 'analyst-1'}, clear=False)
        self.config.start()
        api.service = DetectionService()
        self.client = TestClient(api.app, base_url='https://testserver')
        self.headers = {'Authorization': 'Bearer test-secret'}
        self.events = [
            {'timestamp': '2026-11-09T10:00:00Z', 'host': 'host-1', 'user': 'user-1', 'process': 'p', 'command_line': 'curl https://example.org'},
            {'timestamp': '2026-11-09T10:01:00Z', 'host': 'host-2', 'user': 'user-2', 'process': 'p', 'command_line': 'wget https://example.org', 'event_id': 'existing-id'},
        ]

    def tearDown(self):
        self.client.close()
        self.config.stop()

    def test_api_denies_unauthorized_access_and_impersonation(self):
        response = self.client.post('/api/v1/analyze', json={'events': self.events}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        detection_id = response.json()['detections'][0]['detection_id']
        self.assertEqual(self.client.post('/api/v1/analyze', json={'events': self.events}).status_code, 401)
        self.assertEqual(self.client.get('/api/v1/detections').status_code, 401)
        self.assertEqual(self.client.get('/api/v1/detections', headers={'Authorization': 'Bearer wrong'}).status_code, 401)
        self.assertEqual(self.client.post('/api/v1/detections/' + detection_id + '/approval', json={'analyst': 'intruder'}).status_code, 401)
        self.assertEqual(self.client.post('/api/v1/detections/' + detection_id + '/approval', headers=self.headers, json={'analyst': 'intruder'}).status_code, 403)
        approved = self.client.post('/api/v1/detections/' + detection_id + '/approval', headers=self.headers, json={'analyst': 'analyst-1'})
        self.assertEqual(approved.status_code, 200)
        self.assertTrue(approved.json()['simulation_only'])

    def test_generated_event_ids_can_be_mapped_to_input_positions(self):
        response = self.client.post('/api/v1/analyze', json={'events': self.events}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        refs = data['event_refs']
        self.assertEqual([ref['input_index'] for ref in refs], [0, 1])
        self.assertEqual(refs[1]['event_id'], 'existing-id')
        by_host = {d['host']: d['event_ids'] for d in data['detections']}
        self.assertIn(refs[0]['event_id'], by_host['host-1'])
        self.assertIn(refs[1]['event_id'], by_host['host-2'])

    def test_duplicate_event_ids_are_rejected(self):
        events = [dict(event, event_id='same-id') for event in self.events]
        response = self.client.post('/api/v1/analyze', json={'events': events}, headers=self.headers)
        self.assertEqual(response.status_code, 422)
        self.assertIn('duplicate event_id', response.json()['detail'])

    def test_event_ids_that_collide_after_redaction_are_rejected(self):
        ids = ['2001:db8::1', '2001:0db8:0000:0000:0000:0000:0000:0001']
        events = [dict(event, event_id=event_id) for event, event_id in zip(self.events, ids)]
        response = self.client.post('/api/v1/analyze', json={'events': events}, headers=self.headers)
        self.assertEqual(response.status_code, 422)

    def test_missing_configuration_fails_closed(self):
        with patch.dict('os.environ', {'AEGIS_API_TOKEN': ''}):
            self.assertEqual(self.client.get('/api/v1/detections', headers=self.headers).status_code, 503)

    def test_only_authenticated_demo_file_is_exposed(self):
        with NamedTemporaryFile(mode='w', suffix='.json', dir='data', delete=False) as handle:
            handle.write('{"secret": "test-only"}')
            private_file = Path(handle.name)
        try:
            path = '/data/' + private_file.name
            self.assertEqual(self.client.get(path).status_code, 404)
            self.assertEqual(self.client.get(path, headers=self.headers).status_code, 404)
            self.assertEqual(self.client.get('/data/demo_events.json').status_code, 401)
            self.assertEqual(self.client.get('/data/demo_events.json', headers=self.headers).status_code, 200)
        finally:
            private_file.unlink()

    def test_demo_sample_end_to_end(self):
        sample = self.client.get('/data/demo_events.json', headers=self.headers).json()
        result = self.client.post('/api/v1/analyze', json=sample, headers=self.headers)
        self.assertEqual(result.status_code, 200)
        self.assertTrue(result.json()['detections'])
        self.assertEqual(len(result.json()['event_refs']), len(sample['events']))


if __name__ == '__main__':
    unittest.main()
