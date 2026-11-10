"""Explicitly verified public host exceptions must not weaken default masking."""
import json
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from aegis_on import api
from aegis_on.pii import PIIDetector, Span
from aegis_on.pii_reporting import inspect_events
from aegis_on.service import DetectionService


class SurnameModel:
    def find(self, text):
        return [Span(0, 1, 'SURNAME', 'model')] if text == '김' else []


class VerifiedHostTests(unittest.TestCase):
    def test_only_explicitly_verified_host_avoids_ambiguous_substring(self):
        detector = PIIDetector(SurnameModel())
        event = {'user': '김', 'host': '김치서비스'}
        _, safe_default = inspect_events([event], [0], detector)
        self.assertNotIn('김치서비스', safe_default.host('김치서비스'))
        _, mask = inspect_events([event], [0], detector, verified_public_hosts={'김치서비스'})
        self.assertEqual(mask.host('김치서비스'), '김치서비스')
        self.assertNotIn('김', mask.host('김'))
        self.assertNotIn('김', mask.host('김민준-PC'))
        self.assertNotIn('김', mask('김치서비스'))  # other fields are unchanged

    def test_direct_detection_and_conflicting_types_still_mask(self):
        class DirectModel:
            def find(self, text):
                if text in ('김', '김치서비스'):
                    return [Span(0, 1, 'SURNAME', 'model')]
                return []
        _, mask = inspect_events([{'user': '김', 'host': '김치서비스'}], [0], PIIDetector(DirectModel()),
                                 verified_public_hosts=frozenset({'김치서비스'}))
        self.assertNotIn('김', mask.host('김치서비스'))

        class ConflictingModel:
            def find(self, text):
                if text == 'surname 김':
                    return [Span(8, 9, 'SURNAME', 'model')]
                if text == 'username 김':
                    return [Span(9, 10, 'USERNAME', 'model')]
                return []
        _, mask = inspect_events([{'user': 'surname 김', 'process': 'username 김', 'host': '김치서비스'}],
                                 [0], PIIDetector(ConflictingModel()),
                                 verified_public_hosts=frozenset({'김치서비스'}))
        self.assertNotIn('김', mask.host('김치서비스'))

    def test_host_exception_does_not_exempt_other_pii_or_fields(self):
        event = {'user': '김', 'host': '김치서비스 analyst@example.test 010-1234-5678 192.0.2.1'}
        _, mask = inspect_events([event], [0], PIIDetector(SurnameModel()),
                                 verified_public_hosts=frozenset({event['host']}))
        displayed = mask.host(event['host'])
        self.assertIn('김치서비스', displayed)
        for value in ('analyst@example.test', '010-1234-5678', '192.0.2.1'):
            self.assertNotIn(value, displayed)
        for value in ('김', 'DOMAIN\\김', '/Users/김', '김민준-PC'):
            self.assertNotIn('김', mask(value))
        self.assertNotEqual(mask.host(event['host'] + 'x'), event['host'] + 'x')

    def test_api_settings_and_result_paths(self):
        old_service, old_detector = api.service, api.pii_detector
        self.addCleanup(setattr, api, 'service', old_service)
        self.addCleanup(setattr, api, 'pii_detector', old_detector)
        api.service, api.pii_detector = DetectionService(), PIIDetector(SurnameModel())
        env = {'AEGIS_API_TOKEN': 'test-token', 'AEGIS_ANALYST_NAME': 'analyst',
               'AEGIS_PII_VERIFIED_PUBLIC_HOSTS': json.dumps(['김치서비스'], ensure_ascii=False)}
        with patch.dict('os.environ', env, clear=True), TestClient(api.app, base_url='https://testserver') as client:
            headers = {'Authorization': 'Bearer test-token'}
            event = {'timestamp': '2026-01-01T00:00:00Z', 'host': '김치서비스', 'user': '김',
                     'process': 'curl', 'event_id': 'id-김치서비스', 'command_line': 'curl /Users/김'}
            response = client.post('/api/v1/analyze', json={'events': [event]}, headers=headers)
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data['pii']['verified_public_hosts'], 'enabled')
            self.assertEqual(data['detections'][0]['host'], '김치서비스')
            self.assertNotIn('id-김치서비스', response.text)
            self.assertNotIn('/Users/김', response.text)
            self.assertEqual(client.get('/api/v1/detections', headers=headers).json()['detections'][0]['host'], '김치서비스')
            result = client.post('/api/v1/detections/' + data['detections'][0]['detection_id'] + '/approval',
                                 headers=headers, json={'analyst': 'analyst', 'rationale': '김'})
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.json()['detection']['host'], '김치서비스')
            self.assertNotIn('analyst rationale: 김', result.text)

            sysmon = {'System': {'Provider': 'Microsoft-Windows-Sysmon', 'EventID': 1,
                                 'TimeCreated': '2026-01-01T00:00:00Z', 'Computer': '김치서비스',
                                 'Channel': 'Microsoft-Windows-Sysmon/Operational'},
                      'EventData': {'Image': r'C:\\curl.exe', 'User': '김', 'CommandLine': 'curl /Users/김'}}
            result = client.post('/api/v1/sysmon/analyze', json={'events': [sysmon]}, headers=headers)
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.json()['source_events'][0]['host'], '김치서비스')
            self.assertEqual(result.json()['detections'][0]['host'], '김치서비스')
            with patch.dict('os.environ', {'AEGIS_PII_VERIFIED_PUBLIC_HOSTS': '{invalid'}):
                self.assertEqual(client.get('/api/v1/pii/status', headers=headers).json()['verified_public_hosts'], 'invalid')
                listing = client.get('/api/v1/detections', headers=headers).json()['detections']
                self.assertTrue(all(item['host'] != '김치서비스' for item in listing))
                prior = client.post('/api/v1/detections/' + data['detections'][0]['detection_id'] + '/approval',
                                    headers=headers, json={'analyst': 'analyst', 'rationale': '김'})
                self.assertNotEqual(prior.json()['detection']['host'], '김치서비스')
                response = client.post('/api/v1/analyze', json={'events': [dict(event, event_id='other-id')]}, headers=headers)
                self.assertEqual(response.status_code, 200)
                self.assertNotEqual(response.json()['detections'][0]['host'], '김치서비스')


if __name__ == '__main__':
    unittest.main()
