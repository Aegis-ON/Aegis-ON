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


class ContextNameModel:
    def find(self, text):
        return [Span(m.start(), m.end(), 'GIVENNAME', 'model')
                for m in re.finditer('JaneDoe', text) if '@' in text]


class CrossFieldOverlapModel:
    def find(self, text):
        if text == 'JaneDoe':
            return [Span(0, 7, 'GIVENNAME', 'model')]
        if text == 'curl DoeLee':
            return [Span(5, 11, 'SURNAME', 'model')]
        return []


class NumericModel:
    def find(self, text):
        return [Span(m.start(), m.end(), 'ACCOUNTNUM', 'model') for m in re.finditer('1234567890', text)]


class CaseVariantModel:
    def find(self, text):
        return [Span(m.start(), m.end(), 'GIVENNAME', 'model') for m in re.finditer('ERASE', text)]


class TimestampModel:
    def __init__(self, value='2026-01-01T00:00:00Z'):
        self.value = value

    def find(self, text):
        return [Span(m.start(), m.end(), 'DATEOFBIRTH', 'model')
                for m in re.finditer(re.escape(self.value), text)]


class Ipv6FragmentModel:
    def find(self, text):
        return [Span(0, 4, 'IDCARD', 'model')] if text == '2001' else []


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

    def test_overlapping_candidates_mask_repeated_values_in_other_fields(self):
        event = self.event()
        event.update(host='h01012345678', user='safe', process='curl', event_id='safe-id',
                     command_line='curl 01012345678@example.test')
        response = self.client.post('/api/v1/analyze', json={'events': [event]}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('01012345678', response.text)
        self.assertNotIn('01012345678', self.client.get('/api/v1/detections', headers=self.headers).text)
        found = response.json()['pii']['findings']
        self.assertEqual({f['type'] for f in found}, {'EMAIL', 'TELEPHONENUM'})
        self.assertTrue(next(f for f in found if f['type'] == 'EMAIL')['token'].startswith('[EMAIL:'))
        self.assertTrue(next(f for f in found if f['type'] == 'TELEPHONENUM')['token'].startswith('[PHONE:'))

    def test_overlap_model_candidate_masks_repeated_value_not_detected_in_isolation(self):
        api.pii_detector = PIIDetector(ContextNameModel())
        event = self.event()
        event.update(host='JaneDoe-PC', user='safe', process='curl', event_id='safe-id',
                     command_line='curl JaneDoe@example.test')
        response = self.client.post('/api/v1/analyze', json={'events': [event]}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any(f['type'] == 'GIVENNAME' and f['source'] == 'model' for f in response.json()['pii']['findings']))
        self.assertNotIn('JaneDoe', response.text)
        self.assertNotIn('JaneDoe', self.client.get('/api/v1/detections', headers=self.headers).text)

    def test_overlapping_repeated_values_mask_their_entire_union_in_output(self):
        api.pii_detector = PIIDetector(CrossFieldOverlapModel())
        event = self.event()
        event.update(host='JaneDoeLee-PC', user='JaneDoe', process='curl', event_id='safe-id',
                     command_line='curl DoeLee')
        response = self.client.post('/api/v1/analyze', json={'events': [event]}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual({f['type'] for f in response.json()['pii']['findings']}, {'GIVENNAME', 'SURNAME'})
        self.assertNotIn('JaneDoe', response.text)
        self.assertNotIn('DoeLee', response.text)
        self.assertNotIn('Lee-PC', response.text)
        self.assertNotIn('Lee-PC', self.client.get('/api/v1/detections', headers=self.headers).text)

    def test_detected_value_is_masked_when_engine_lowercases_evidence(self):
        api.pii_detector = PIIDetector(CaseVariantModel())
        event = self.event()
        event.update(host='LAB', user='safe', process='p', event_id='safe-id', command_line='notify ERASE')
        response = self.client.post('/api/v1/analyze', json={'events': [event]}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any(f['source'] == 'model' for f in response.json()['pii']['findings']))
        self.assertNotIn('erase', response.text.lower())
        self.assertNotIn('erase', self.client.get('/api/v1/detections', headers=self.headers).text.lower())

    def test_detected_timestamp_is_masked_after_correlation_normalizes_it(self):
        api.pii_detector = PIIDetector(TimestampModel())
        events = []
        for i in range(3):
            event = self.event()
            event.update(host='LAB', user='safe', process='p', event_id=f'id-{i}',
                         timestamp='2026-01-01T00:00:00Z',
                         command_line='notify 2026-01-01T00:00:00Z', destination=f'192.0.2.{i+1}')
            events.append(event)
        response = self.client.post('/api/v1/analyze', json={'events': events}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any(d['source'] == 'correlation' for d in response.json()['detections']))
        self.assertTrue(any(f['type'] == 'DATEOFBIRTH' for f in response.json()['pii']['findings']))
        for text in (response.text, self.client.get('/api/v1/detections', headers=self.headers).text):
            self.assertNotIn('2026-01-01T00:00:00Z', text)
            self.assertNotIn('2026-01-01T00:00:00+00:00', text)

    def test_detected_basic_iso_date_is_masked_after_correlation_normalizes_it(self):
        api.pii_detector = PIIDetector(TimestampModel('20260101'))
        events = []
        for i in range(3):
            event = self.event()
            event.update(host='LAB', user='safe', process='p', event_id=f'id-{i}',
                         timestamp='20260101', command_line='notify 20260101',
                         destination=f'192.0.2.{i+1}')
            events.append(event)
        response = self.client.post('/api/v1/analyze', json={'events': events}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any(d['source'] == 'correlation' for d in response.json()['detections']))
        for text in (response.text, self.client.get('/api/v1/detections', headers=self.headers).text):
            self.assertNotIn('20260101', text)
            self.assertNotIn('2026-01-01T00:00:00+00:00', text)

    def test_display_token_matches_final_global_overlap_replacement(self):
        event = self.event()
        event.update(host='a@b.co@c.io', user='b.co@c.io', process='curl', event_id='safe-id',
                     command_line='curl safe')
        response = self.client.post('/api/v1/analyze', json={'events': [event]}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        host_finding = next(f for f in data['pii']['findings'] if f['field'] == 'host')
        self.assertEqual(host_finding['display_token'], data['detections'][0]['host'])
        self.assertNotIn('a@b.co', response.text)

    def test_approval_analyst_is_pseudonymized_when_detected_in_rationale(self):
        api.pii_detector = PIIDetector(ContextNameModel())
        with patch.dict('os.environ', {'AEGIS_ANALYST_NAME': 'JaneDoe'}):
            event = self.event()
            event.update(host='safe-host', user='safe', process='curl', event_id='safe-id', command_line='curl safe')
            response = self.client.post('/api/v1/analyze', json={'events': [event]}, headers=self.headers)
            detection_id = response.json()['detections'][0]['detection_id']
            approved = self.client.post('/api/v1/detections/' + detection_id + '/approval', headers=self.headers,
                                        json={'analyst': 'JaneDoe', 'rationale': 'approved JaneDoe@example.test'})
            self.assertEqual(approved.status_code, 200)
            self.assertNotIn('JaneDoe', approved.text)
            self.assertNotIn('JaneDoe', self.client.get('/api/v1/detections', headers=self.headers).text)

    def test_detected_candidate_is_masked_in_sysmon_metadata(self):
        api.pii_detector = PIIDetector(UUIDModel())
        guid = '12345678-1234-1234-1234-123456789abc'
        event = {'System': {'Provider': 'Microsoft-Windows-Sysmon', 'EventID': 1,
                            'TimeCreated': '2026-01-01T00:00:00Z', 'Computer': 'LAB',
                            'Channel': 'Microsoft-Windows-Sysmon/Operational'},
                 'EventData': {'Image': r'C:\curl.exe', 'CommandLine': 'curl ' + guid, 'ProcessGuid': guid}}
        response = self.client.post('/api/v1/sysmon/analyze', json={'events': [event]}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any(f['type'] == 'IDCARD' for f in response.json()['pii']['findings']))
        self.assertNotIn(guid, response.text)

    def test_detected_numeric_candidate_is_masked_in_sysmon_metadata(self):
        api.pii_detector = PIIDetector(NumericModel())
        event = {'System': {'Provider': 'Microsoft-Windows-Sysmon', 'EventID': 1,
                            'EventRecordID': 1234567890,
                            'TimeCreated': '2026-01-01T00:00:00Z', 'Computer': 'LAB',
                            'Channel': 'Microsoft-Windows-Sysmon/Operational'},
                 'EventData': {'Image': r'C:\curl.exe', 'CommandLine': 'curl 1234567890', 'ProcessId': 1234567890}}
        unsupported = {'System': {'Provider': 'Microsoft-Windows-Sysmon', 'EventID': 1234567890}, 'EventData': {}}
        response = self.client.post('/api/v1/sysmon/analyze', json={'events': [event, unsupported]}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any(f['type'] == 'ACCOUNTNUM' for f in response.json()['pii']['findings']))
        self.assertNotIn('1234567890', response.text)

    def test_normalizing_ip_cannot_expose_a_detected_ipv6_fragment(self):
        api.pii_detector = PIIDetector(Ipv6FragmentModel())
        event = {'System': {'Provider': 'Microsoft-Windows-Sysmon', 'EventID': 3,
                            'TimeCreated': '2026-01-01T00:00:00Z', 'Computer': 'LAB',
                            'Channel': 'Microsoft-Windows-Sysmon/Operational'},
                 'EventData': {'Image': r'C:\curl.exe', 'User': '2001',
                               'SourceIp': '2001:0db8:0001:0002:0003:0004:0005:0006',
                               'DestinationIp': '192.0.2.17', 'Initiated': 'true'}}
        response = self.client.post('/api/v1/sysmon/analyze', json={'events': [event]}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        source = payload['source_events'][0]['source_ip']
        finding = next(f for f in payload['pii']['findings'] if f['field'] == 'source_ip' and f['type'] == 'IP_ADDRESS')
        self.assertEqual(source, finding['display_token'])
        self.assertTrue(source.startswith('[IP:'))
        self.assertNotIn(':db8:1:2:3:4:5:6', response.text)


if __name__ == '__main__':
    unittest.main()
