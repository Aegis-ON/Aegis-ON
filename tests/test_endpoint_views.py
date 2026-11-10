"""Endpoint observations are derived from sanitized per-batch history only."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from aegis_on import api
from aegis_on.attack_model import AttackModel
from aegis_on.endpoint_views import build_endpoint_groups
from aegis_on.history_store import SQLiteHistory, HistoryError
from aegis_on.pii import PIIDetector
from aegis_on.service import DetectionService
from test_sysmon_api import make_event


class EndpointApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        old = api.service, api.pii_detector, api.attack_model
        self.addCleanup(lambda: (setattr(api, 'service', old[0]), setattr(api, 'pii_detector', old[1]), setattr(api, 'attack_model', old[2])))
        self.path = Path(self.tmp.name) / 'history.sqlite3'
        api.service = DetectionService(SQLiteHistory(self.path))
        api.pii_detector = PIIDetector(); api.attack_model = AttackModel()
        config = patch.dict('os.environ', {'AEGIS_API_TOKEN':'endpoint-fake-token', 'AEGIS_ANALYST_NAME':'analyst-1'}, clear=False)
        config.start(); self.addCleanup(config.stop)
        self.client = TestClient(api.app, base_url='https://testserver'); self.addCleanup(self.client.close)
        self.headers = {'Authorization':'Bearer endpoint-fake-token'}

    def test_auth_empty_and_storage_failure(self):
        self.assertEqual(self.client.get('/api/v1/endpoints').status_code, 401)
        self.assertEqual(self.client.get('/api/v1/endpoints/' + 'a'*64).status_code, 401)
        self.assertEqual(self.client.get('/api/v1/endpoints', headers=self.headers).json()['endpoints'], [])
        self.assertEqual(self.client.get('/api/v1/endpoints/not-an-id', headers=self.headers).status_code, 404)
        with patch.object(api.service.history, 'list_snapshot', side_effect=HistoryError('private path')):
            result = self.client.get('/api/v1/endpoints', headers=self.headers)
            self.assertEqual(result.status_code, 503)
            self.assertNotIn('private path', result.text)

    def test_sysmon_groups_sources_detections_and_approval_after_restart(self):
        first = make_event(1, 1); second = make_event(1, 2); third = make_event(1, 3)
        second['EventData']['CommandLine'] = 'notepad.exe'
        third['System']['Computer'] = 'LAB-02'
        third['EventData']['CommandLine'] = 'notepad.exe'
        response = self.client.post('/api/v1/sysmon/analyze', json={'events':[first,second,third]}, headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json(); detection = data['detections'][0]['detection_id']
        approved = self.client.post(f'/api/v1/detections/{detection}/approval', headers=self.headers,
                                    json={'analyst':'analyst-1', 'rationale':'synthetic review'})
        self.assertEqual(approved.status_code, 200)
        api.service = DetectionService(SQLiteHistory(self.path))
        rows = self.client.get('/api/v1/endpoints', headers=self.headers).json()['endpoints']
        self.assertEqual(sorted(e['event_count'] for e in rows), [1,2])
        row = next(e for e in rows if e['event_count'] == 2)
        detail = self.client.get('/api/v1/endpoints/' + row['endpoint_id'], headers=self.headers).json()
        self.assertEqual(detail['endpoint']['analysis_id'], data['analysis_id'])
        self.assertEqual(len(detail['events']), 2)
        self.assertTrue(any(d.get('approval',{}).get('simulation_only') for d in detail['detections']))
        self.assertTrue(all(d['event_ids'][0] in {e['event_id'] for e in detail['events']} for d in detail['detections']))
        self.assertTrue(row['last_seen'])
        text = str(detail)
        for secret in ['alice@example.org', r'C:\Users\alice', 'https://example.org/tool', 'LAB-01']:
            self.assertNotIn(secret, text)

    def test_json_unknown_and_no_cross_batch_merging(self):
        event = {'timestamp':'2026-01-01T00:00:00Z', 'host':'lab-1', 'user':'u',
                 'process':'notepad.exe', 'command_line':'notepad.exe', 'event_id':'normal-event'}
        for _ in range(2):
            result = self.client.post('/api/v1/analyze', json={'events':[event]}, headers=self.headers)
            self.assertEqual(result.status_code, 200, result.text)
        rows = self.client.get('/api/v1/endpoints', headers=self.headers).json()['endpoints']
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(e['host'] is None and e['attribution'] == 'unknown' for e in rows))
        self.assertNotEqual(rows[0]['endpoint_id'], rows[1]['endpoint_id'])
        self.assertIsNone(rows[0]['last_seen'])

    def test_json_detections_link_only_their_known_event_references(self):
        events = [
            {'timestamp':'2026-01-01T00:00:00Z', 'host':'lab-1', 'user':'u',
             'process':'curl', 'command_line':'curl https://example.invalid', 'event_id':'download'},
            {'timestamp':'2026-01-01T00:00:01Z', 'host':'lab-2', 'user':'u',
             'process':'notepad.exe', 'command_line':'notepad.exe', 'event_id':'normal'},
        ]
        result = self.client.post('/api/v1/analyze', json={'events':events}, headers=self.headers)
        self.assertEqual(result.status_code, 200, result.text)
        rows = self.client.get('/api/v1/endpoints', headers=self.headers).json()['endpoints']
        known = next(e for e in rows if e['attribution'] == 'detection_reference')
        unknown = next(e for e in rows if e['attribution'] == 'unknown')
        self.assertEqual((known['event_count'], unknown['event_count']), (1, 1))
        detail = self.client.get('/api/v1/endpoints/' + known['endpoint_id'], headers=self.headers).json()
        self.assertEqual(detail['events'][0]['input_index'], 0)
        self.assertTrue(all(detail['events'][0]['event_id'] in d['event_ids'] for d in detail['detections']))
        self.assertNotIn('example.invalid', str(detail))

    def test_same_sysmon_host_in_two_batches_is_not_identity_merged(self):
        for _ in range(2):
            result = self.client.post('/api/v1/sysmon/analyze', json={'events':[make_event()]}, headers=self.headers)
            self.assertEqual(result.status_code, 200, result.text)
        rows = self.client.get('/api/v1/endpoints', headers=self.headers).json()['endpoints']
        self.assertEqual(len(rows), 2)
        self.assertNotEqual(rows[0]['analysis_id'], rows[1]['analysis_id'])
        self.assertNotEqual(rows[0]['endpoint_id'], rows[1]['endpoint_id'])


class EndpointAggregationTests(unittest.TestCase):
    def test_ambiguous_legacy_event_is_not_assigned_to_both_hosts(self):
        batch = {'analysis_id':'a', 'input_type':'json', 'detection_ids':['d1','d2'],
                 'event_refs':[{'event_id':'e1','input_index':0}]}
        ds = [{'detection_id':'d1','host':'[HOST:1]','event_ids':['e1'],'score':20},
              {'detection_id':'d2','host':'[HOST:2]','event_ids':['e1'],'score':40}]
        groups = build_endpoint_groups([batch], ds)
        self.assertEqual(len(groups), 3)
        unknown = next(g for g in groups if g['host'] is None)
        self.assertEqual([x['event_id'] for x in unknown['events']], ['e1'])
        self.assertTrue(all(not g['events'] for g in groups if g['host'] is not None))

    def test_cross_batch_detection_is_linked_to_each_observation(self):
        analyses = [{'analysis_id':'a','input_type':'sysmon','detection_ids':[],
                     'source_events':[{'event_id':'one','host':'[HOST:1]'}]},
                    {'analysis_id':'b','input_type':'sysmon','detection_ids':['d'],
                     'source_events':[{'event_id':'two','host':'[HOST:1]'}]}]
        detections = [{'detection_id':'d','host':'[HOST:1]','event_ids':['one','two'],'score':70}]
        groups = build_endpoint_groups(analyses,detections)
        self.assertEqual(len(groups),2)
        self.assertTrue(all(g['detection_count']==1 for g in groups))
        self.assertEqual({g['events'][0]['event_id'] for g in groups},{'one','two'})

    def test_stream_host_group_merges_batches_only_for_same_collector_key(self):
        analyses = [{'analysis_id':'a','input_type':'sysmon','detection_ids':[],
                     'source_events':[{'event_id':'one','host':'[HOST:1]','endpoint_group':'key-a'}]},
                    {'analysis_id':'b','input_type':'sysmon','detection_ids':['d'],
                     'source_events':[{'event_id':'two','host':'[HOST:1]','endpoint_group':'key-a'},
                                      {'event_id':'three','host':'[HOST:1]','endpoint_group':'key-b'}]}]
        detections = [{'detection_id':'d','host':'[HOST:1]','event_ids':['one','two'],'score':70}]
        groups=build_endpoint_groups(analyses,detections)
        self.assertEqual(len(groups),2)
        combined=next(g for g in groups if g['event_count']==2)
        self.assertEqual(combined['detection_count'],1)
        self.assertEqual(set(combined['analysis_ids']),{'a','b'})
        self.assertEqual(combined['identity_scope'],'collector_host_observation')

    def test_missing_sysmon_hosts_are_not_combined(self):
        batch = {'analysis_id':'a', 'input_type':'sysmon', 'detection_ids':[],
                 'source_events':[{'event_id':'e1'}, {'event_id':'e2'}]}
        groups = build_endpoint_groups([batch], [])
        self.assertEqual(len(groups), 2)
        self.assertEqual([g['event_count'] for g in groups], [1,1])
        self.assertTrue(all(g['host'] is None for g in groups))

if __name__ == '__main__': unittest.main()
