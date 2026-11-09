import copy
import json
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from aegis_on import api
from aegis_on.service import DetectionService


def make_event(kind=1, record=1):
    event = {
        'System': {'Provider': 'Microsoft-Windows-Sysmon', 'EventID': kind,
                   'TimeCreated': '2026-11-09T10:00:00Z', 'Computer': 'LAB-01',
                   'EventRecordID': record, 'Channel': 'Microsoft-Windows-Sysmon/Operational'},
        'EventData': {'UtcTime': '2026-11-09 10:00:00.000',
                      'Image': r'C:\Users\alice\curl.exe', 'User': 'alice@example.org',
                      'ProcessGuid': '{00000000-0000-0000-0000-000000000001}',
                      'ProcessId': 123},
    }
    if kind == 1:
        event['EventData']['CommandLine'] = 'curl https://example.org/tool'
        event['EventData']['ParentImage'] = r'C:\Windows\system32\cmd.exe'
    if kind == 3:
        event['EventData'].update({'Initiated': 'true', 'SourceIp': '192.0.2.9', 'SourcePort': 50000,
                                   'DestinationIp': '198.51.100.1', 'DestinationPort': 443})
    return event


class SysmonApiTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict('os.environ', {'AEGIS_API_TOKEN': 'test-secret', 'AEGIS_ANALYST_NAME': 'analyst-1'}, clear=False)
        self.env.start()
        api.service = DetectionService()
        self.client = TestClient(api.app)
        self.headers = {'Authorization': 'Bearer test-secret'}

    def tearDown(self):
        self.client.close()
        self.env.stop()

    def post(self, events):
        return self.client.post('/api/v1/sysmon/analyze', json={'events': events}, headers=self.headers)

    def test_process_detection_links_to_original_and_omits_sensitive_details(self):
        result = self.post([make_event()])
        self.assertEqual(result.status_code, 200, result.text)
        data = result.json()
        self.assertEqual(data['summary'], {'total': 1, 'processed': 1, 'invalid': 0, 'unsupported': 0})
        event = data['source_events'][0]
        self.assertEqual(str(event['record_id']), '1')
        self.assertEqual(event['sysmon_event_id'], 1)
        self.assertEqual(event['log_source'], 'Microsoft-Windows-Sysmon/Operational')
        self.assertTrue(any(d['technique'] == 'T1105' and event['event_id'] in d['event_ids'] for d in data['detections']))
        for secret in ['alice@example.org', r'C:\Users\alice', 'https://example.org/tool']:
            self.assertNotIn(secret, result.text)
        self.assertNotIn('CommandLine', result.text)

    def test_sysmon_rule_evidence_does_not_echo_secrets_in_matched_command(self):
        event = make_event()
        event['EventData']['CommandLine'] = 'rm --custom=SECRET123 -r /tmp/data'
        result = self.post([event])
        self.assertEqual(result.status_code, 200)
        self.assertTrue(any(d['technique'] == 'T1485' for d in result.json()['detections']))
        self.assertNotIn('SECRET123', result.text)
        stored = self.client.get('/api/v1/detections', headers=self.headers)
        self.assertNotIn('SECRET123', stored.text)

    def test_network_fanout_links_only_connections_and_explains_condition(self):
        events = []
        for i in range(3):
            e = make_event(3, 10 + i)
            e['EventData']['Image'] = r'C:\Windows\powershell.exe'
            e['EventData']['DestinationIp'] = f'198.51.100.{i+1}'
            e['EventData']['UtcTime'] = f'2026-11-09 10:0{i}:00.000'
            events.append(e)
        unrelated = make_event(1, 20)
        unrelated['EventData']['CommandLine'] = 'notepad.exe'
        events.append(unrelated)
        result = self.post(events)
        self.assertEqual(result.status_code, 200, result.text)
        data = result.json()
        self.assertEqual(data['summary']['processed'], 4)
        correlations = [d for d in data['detections'] if d['source'] == 'correlation']
        self.assertEqual(len(correlations), 1)
        corr = correlations[0]
        expected = {e['event_id'] for e in data['source_events'] if e['sysmon_event_id'] == 3}
        self.assertEqual(set(corr['event_ids']), expected)
        evidence = ' '.join(corr['evidence']).lower()
        for expected_text in ['2026-11-09', '3 unique destinations', 'related connection events: 3', 'at least 3', '10 minutes', 'not proof']:
            self.assertIn(expected_text, evidence)
        for d in data['detections']:
            if set(d['event_ids']) & expected:
                self.assertEqual(d['source'], 'correlation')
        self.assertNotIn('198.51.100.1', result.text)

    def test_sysmon_hosts_are_correlated_case_insensitively(self):
        events = []
        for i, host in enumerate(['LAB-01', 'lab-01', 'Lab-01']):
            event = make_event(3, 100 + i)
            event['System']['Computer'] = host
            event['EventData']['DestinationIp'] = f'198.51.100.{i+1}'
            events.append(event)
        result = self.post(events)
        self.assertEqual(result.status_code, 200)
        matches = [d for d in result.json()['detections'] if d['source'] == 'correlation']
        self.assertEqual(len(matches), 1)
        self.assertEqual(len(matches[0]['event_ids']), 3)

    def test_equivalent_ipv6_destinations_are_not_counted_as_distinct(self):
        events = []
        for i, address in enumerate(['2001:db8::1', '2001:0db8:0000:0000:0000:0000:0000:0001', '2001:DB8::1']):
            event = make_event(3, 200 + i)
            event['EventData']['DestinationIp'] = address
            events.append(event)
        result = self.post(events)
        self.assertEqual(result.status_code, 200)
        self.assertFalse(any(d['source'] == 'correlation' for d in result.json()['detections']))

    def test_upper_timestamp_boundary_does_not_crash_correlation(self):
        events = []
        for i in range(3):
            event = make_event(3, 300 + i)
            event['EventData']['UtcTime'] = '9999-12-31 23:59:59'
            event['EventData']['DestinationIp'] = f'198.51.100.{i+1}'
            events.append(event)
        result = self.post(events)
        self.assertEqual(result.status_code, 200)
        self.assertTrue(any(d['source'] == 'correlation' for d in result.json()['detections']))

    def test_partial_batch_unsupported_invalid_and_duplicate_ids(self):
        bad = make_event(1, 2)
        bad['EventData'].pop('Image')
        unsupported = make_event(22, 3)
        duplicate = make_event(1, 1)
        missing_record = make_event(1, 4)
        missing_record['System'].pop('EventRecordID')
        result = self.post([make_event(), bad, unsupported, duplicate, missing_record])
        self.assertEqual(result.status_code, 200, result.text)
        data = result.json()
        self.assertEqual(data['summary'], {'total': 5, 'processed': 2, 'invalid': 2, 'unsupported': 1})
        self.assertEqual([i['status'] for i in data['items']], ['processed','invalid','unsupported','invalid','processed'])
        self.assertEqual(data['items'][2]['sysmon_event_id'], 22)
        self.assertEqual(len({e['event_id'] for e in data['source_events']}), 2)
        self.assertTrue(all('reason' in i for i in data['items'] if i['status'] != 'processed'))
        self.assertEqual([e['input_index'] for e in data['source_events']], [0, 4])

    def test_out_of_range_timestamp_does_not_fail_valid_events(self):
        bad = make_event(1, 2)
        bad['EventData']['UtcTime'] = ''
        bad['System']['TimeCreated'] = '0001-01-01T00:00:00+14:00'
        result = self.post([bad, make_event()])
        self.assertEqual(result.status_code, 200)
        self.assertEqual([item['status'] for item in result.json()['items']], ['invalid', 'processed'])

    def test_auth_body_limit_malformed_and_unsafe_json(self):
        url = '/api/v1/sysmon/analyze'
        self.assertEqual(self.client.post(url, json={'events': []}).status_code, 401)
        self.assertEqual(self.client.post(url, content=b'{}', headers={**self.headers, 'Content-Type': 'text/plain'}).status_code, 415)
        headers = {**self.headers, 'Content-Type': 'application/json'}
        for payload in [b'{', b'\xff', b'{"events":[],"events":[]}', b'{"events":[NaN]}']:
            self.assertEqual(self.client.post(url, content=payload, headers=headers).status_code, 422)
        self.assertEqual(self.client.post(url, content=b' ' * (2*1024*1024+1), headers=headers).status_code, 413)
        self.assertEqual(self.post([make_event()] * 1001).status_code, 422)

    def test_empty_and_all_bad_batch_do_not_fail(self):
        empty = self.post([])
        self.assertEqual(empty.status_code, 200)
        self.assertEqual(empty.json()['summary']['total'], 0)
        self.assertEqual(empty.json()['detections'], [])
        bad = self.post([{'invalid': 'alice@example.org'}])
        self.assertEqual(bad.status_code, 200)
        self.assertEqual(bad.json()['summary']['invalid'], 1)
        self.assertNotIn('alice@example.org', bad.text)

    def test_windows_powershell_utf8_bom_and_missing_optional_fields(self):
        event = make_event(3)
        event['EventData'].pop('User')
        body = b'\xef\xbb\xbf' + json.dumps({'events': [event]}).encode('utf-8')
        response = self.client.post('/api/v1/sysmon/analyze', content=body,
                                    headers={**self.headers, 'Content-Type': 'application/json'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['summary']['processed'], 1)
        self.assertEqual(response.json()['detections'], [])

    def test_legacy_json_cannot_spoof_sysmon_metadata(self):
        event = {'timestamp': '2026-11-09T10:00:00Z', 'host': 'legacy', 'user': 'user',
                 'process': 'bash', 'command_line': 'rm --custom=example -r /tmp',
                 'source_metadata': {'sysmon_event_id': 1}}
        response = self.client.post('/api/v1/analyze', json={'events': [event]}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any('matched pattern:' in ' '.join(d['evidence']) for d in response.json()['detections']))

if __name__ == '__main__':
    unittest.main()
