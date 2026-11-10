"""Host exceptions do not bypass regex fallback or model failure behavior."""
import json
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from aegis_on import api
from aegis_on.pii import PIIDetector
from aegis_on.service import DetectionService


class BrokenModel:
    def find(self, text):
        raise RuntimeError('synthetic private value')


class VerifiedHostFailureTests(unittest.TestCase):
    def test_disabled_load_error_and_inference_failure(self):
        old_service, old_detector = api.service, api.pii_detector
        self.addCleanup(setattr, api, 'service', old_service)
        self.addCleanup(setattr, api, 'pii_detector', old_detector)
        api.service = DetectionService()
        host = 'analyst@example.test'
        event = {'timestamp': '2026-01-01T00:00:00Z', 'host': host, 'user': 'safe',
                 'process': 'curl', 'event_id': 'id', 'command_line': 'curl example.test'}
        env = {'AEGIS_API_TOKEN': 'test-token', 'AEGIS_ANALYST_NAME': 'analyst',
               'AEGIS_PII_VERIFIED_PUBLIC_HOSTS': json.dumps([host])}
        with patch.dict('os.environ', env, clear=True), TestClient(api.app, base_url='https://testserver') as client:
            headers = {'Authorization': 'Bearer test-token'}
            for detector in (PIIDetector(), PIIDetector(state='error', reason='synthetic load failure')):
                api.pii_detector = detector
                result = client.post('/api/v1/analyze', json={'events': [event]}, headers=headers)
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.json()['pii']['state'], detector.status()['state'])
                self.assertNotIn(host, result.text)
            api.pii_detector = PIIDetector(BrokenModel())
            result = client.post('/api/v1/analyze', json={'events': [event]}, headers=headers)
            self.assertEqual(result.status_code, 503)
            self.assertNotIn(host, result.text)
            self.assertNotIn('synthetic private value', result.text)
            self.assertEqual(client.get('/api/v1/pii/status', headers=headers).json()['state'], 'error')


if __name__ == '__main__':
    unittest.main()
