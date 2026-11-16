"""Authenticated, idempotent batch ingestion over real temporary SQLite files."""
import concurrent.futures
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from aegis_on import api
from aegis_on.attack_model import AttackModel
from aegis_on.history_store import HistoryError, SQLiteHistory
from aegis_on.pii import PIIDetector
from aegis_on.service import DetectionService
from test_sysmon_api import make_event


class IngestionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'history.sqlite3'
        old = api.service, api.pii_detector, api.attack_model
        self.addCleanup(lambda: (setattr(api,'service',old[0]),setattr(api,'pii_detector',old[1]),setattr(api,'attack_model',old[2])))
        api.service = DetectionService(SQLiteHistory(self.path)); api.pii_detector = PIIDetector(); api.attack_model = AttackModel()
        env = patch.dict('os.environ', {'AEGIS_API_TOKEN':'synthetic-token', 'AEGIS_ANALYST_NAME':'analyst-1', 'AEGIS_ALLOW_LEGACY_COLLECTOR_TOKEN':'1'}, clear=False)
        env.start(); self.addCleanup(env.stop)
        self.client = TestClient(api.app, base_url='https://testserver'); self.addCleanup(self.client.close)
        self.headers = {'Authorization':'Bearer synthetic-token','X-Collector-ID':'fixture-collector','Idempotency-Key':'batch-1'}
        self.body = {'events':[make_event()]}

    def test_auth_replay_conflict_and_restart(self):
        self.assertEqual(self.client.post('/api/v1/ingest/sysmon',json=self.body).status_code,401)
        self.assertEqual(self.client.get('/api/v1/collectors').status_code,401)
        first = self.client.post('/api/v1/ingest/sysmon',json=self.body,headers=self.headers)
        self.assertEqual(first.status_code,200,first.text)
        self.assertFalse(first.json()['replayed'])
        data = first.json(); api.service = DetectionService(SQLiteHistory(self.path))
        # A committed retry does not require the model to run a second time.
        with patch.object(api.pii_detector, 'find', side_effect=RuntimeError('temporary model error')):
            second = self.client.post('/api/v1/ingest/sysmon',json=self.body,headers=self.headers)
        self.assertEqual(second.status_code,200,second.text)
        self.assertTrue(second.json()['replayed']); self.assertEqual(second.json()['analysis_id'],data['analysis_id'])
        changed = self.client.post('/api/v1/ingest/sysmon',json={'events':[make_event(1,2)]},headers=self.headers)
        self.assertEqual(changed.status_code,409)
        self.assertEqual(len(self.client.get('/api/v1/history',headers=self.headers).json()['analyses']),1)
        state = self.client.get('/api/v1/collectors',headers=self.headers).json()['collectors'][0]
        self.assertTrue(state['last_received_at']); self.assertIsNone(state['reported_state'])
        for path in self.path.parent.iterdir():
            if path.is_file():
                raw=path.read_bytes()
                self.assertNotIn(b'synthetic-token',raw)
                self.assertNotIn(b'alice@example.org',raw)
                self.assertNotIn(b'https://example.org/tool',raw)

    def test_partial_sysmon_batch_rejected_without_any_history(self):
        response = self.client.post('/api/v1/ingest/sysmon', json={'events':[make_event(1,1),make_event(2,2)]}, headers=self.headers)
        self.assertEqual(response.status_code,422)
        self.assertEqual(self.client.get('/api/v1/history',headers=self.headers).json()['analyses'],[])
        manual = self.client.post('/api/v1/sysmon/analyze',json={'events':[make_event(1,1),make_event(2,2)]},headers=self.headers)
        self.assertEqual(manual.status_code,200)
        self.assertEqual(manual.json()['summary']['processed'],1)

    def test_json_ingestion_and_heartbeat_validation(self):
        event={'timestamp':'2026-01-01T00:00:00Z','host':'fake','user':'demo','process':'curl','command_line':'curl https://example.invalid','event_id':'x'}
        response = self.client.post('/api/v1/ingest/json',json={'events':[event]},headers=self.headers)
        self.assertEqual(response.status_code,200,response.text)
        endpoint='/api/v1/collectors/fixture-collector/heartbeat'
        self.assertEqual(self.client.post(endpoint,json={'state':'error','error_code':'contains fake secret'},headers=self.headers).status_code,422)
        self.assertEqual(self.client.post(endpoint,json={'state':'error','error_code':'read_error'},headers=self.headers).status_code,200)
        self.assertEqual(self.client.post(endpoint,json={'state':'running'},headers=self.headers).status_code,200)
        state=self.client.get('/api/v1/collectors',headers=self.headers).json()['collectors'][0]
        self.assertEqual(state['reported_state'],'running'); self.assertEqual(state['last_error_code'],'read_error')
        self.assertTrue(state['last_error_at']); self.assertTrue(state['last_heartbeat_at'])
        self.assertEqual(self.client.post(endpoint,json={'state':'running','error_code':'read_error'},headers=self.headers).status_code,422)
        self.assertEqual(self.client.post('/api/v1/collectors/synthetic-token/heartbeat',json={'state':'running'},headers=self.headers).status_code,422)

    def test_storage_failure_and_size_limit_are_not_success(self):
        with patch.object(api.service.history,'save_analysis',side_effect=HistoryError('private')):
            response=self.client.post('/api/v1/ingest/sysmon',json=self.body,headers=self.headers)
        self.assertEqual(response.status_code,503); self.assertNotIn('private',response.text)
        self.assertEqual(self.client.get('/api/v1/history',headers=self.headers).json()['analyses'],[])
        result=self.client.post('/api/v1/ingest/json',content=b' '*(2*1024*1024+1),headers={**self.headers,'Content-Type':'application/json'})
        self.assertEqual(result.status_code,413)

    def test_idempotent_commit_concurrent_processes(self):
        store=SQLiteHistory(self.path);store.list_collectors()
        code = '''import json,sys
from aegis_on.history_store import SQLiteHistory
s=SQLiteHistory(sys.argv[1]);
r=s.save_analysis({'analysis_id':sys.argv[2], 'summary':{'total':1}},[{'detection_id':sys.argv[2],'evidence':[]}],{'collector_id':'c','batch_id':'b','input_type':'json','digest':'a'*64})
print(json.dumps(r,sort_keys=True))
'''
        def invoke(i):
            return subprocess.run([sys.executable,'-c',code,str(self.path),str(i)],capture_output=True,text=True,check=True,env={**os.environ,'PYTHONPATH':'src'}).stdout
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results=[json.loads(x) for x in pool.map(invoke,range(6))]
        self.assertEqual(sum(not r['replayed'] for r in results),1)
        self.assertEqual(len({r['analysis_id'] for r in results}),1)
        self.assertEqual(len(store.list_snapshot()[0]),1)

    def test_upgrade_schema_v1_preserves_analysis_and_approval(self):
        # Existing DB has v1 tables. Migration is an atomic transaction.
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE analyses (sequence INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL)')
            db.execute('CREATE TABLE detections (sequence INTEGER PRIMARY KEY AUTOINCREMENT, analysis_sequence INTEGER NOT NULL REFERENCES analyses(sequence), detection_id TEXT NOT NULL UNIQUE, payload TEXT NOT NULL, approval TEXT)')
            db.execute('INSERT INTO analyses(payload) VALUES (?)', ('{"analysis_id":"old"}',))
            db.execute('INSERT INTO detections(analysis_sequence,detection_id,payload,approval) VALUES (1,?,?,?)',('d','{"detection_id":"d","evidence":[]}','{"simulation_only":true,"rationale":"first"}'))
            db.execute('PRAGMA user_version=1')
        os.chmod(self.path,0o600)
        analyses,detections=SQLiteHistory(self.path).list_snapshot()
        self.assertEqual(analyses[0]['analysis_id'],'old');self.assertEqual(detections[0]['approval']['rationale'],'first')
        with sqlite3.connect(self.path) as db:self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],5)

    def test_separate_batches_fanout_dedup_restart_and_conflict(self):
        events = []
        for i in range(3):
            event = make_event(3, 101+i)
            event['EventData']['DestinationIp'] = f'198.51.100.{i+1}'
            event['EventData']['UtcTime'] = f'2026-11-09 10:0{i}:00.000'
            events.append(event)
        for i, event in enumerate(events):
            if i == 2:
                api.service = DetectionService(SQLiteHistory(self.path))
            response = self.client.post('/api/v1/ingest/sysmon', json={'events':[event]},
                                        headers={**self.headers, 'Idempotency-Key':f'network-{i}'})
            self.assertEqual(response.status_code, 200, response.text)
        snapshot = self.client.get('/api/v1/history', headers=self.headers).json()
        fanout = [d for d in snapshot['detections'] if d['source'] == 'correlation']
        self.assertEqual(len(fanout),1)
        self.assertEqual(len(fanout[0]['event_ids']),3)
        self.assertEqual(set(fanout[0]['event_ids']), {a['source_events'][0]['event_id'] for a in snapshot['analyses']})
        groups = {a['source_events'][0]['endpoint_group'] for a in snapshot['analyses']}
        self.assertEqual(len(groups),1)
        self.assertEqual(len(next(iter(groups))),64)
        self.assertIn('3 unique destinations', ' '.join(fanout[0]['evidence']))
        self.assertTrue(all(a.get('received_at') for a in snapshot['analyses']))
        retry = self.client.post('/api/v1/ingest/sysmon', json={'events':[events[0]]},
                                 headers={**self.headers, 'Idempotency-Key':'different-batch'})
        self.assertEqual(retry.status_code,200,retry.text)
        self.assertEqual(retry.json()['summary']['duplicate'],1)
        after = self.client.get('/api/v1/history', headers=self.headers).json()
        self.assertEqual(len([d for d in after['detections'] if d['source']=='correlation']),1)
        self.assertEqual(sum(len(a['source_events']) for a in after['analyses']),3)
        changed = make_event(3,101); changed['EventData']['DestinationIp']='198.51.100.99'
        collision = self.client.post('/api/v1/ingest/sysmon',json={'events':[changed]},
                                     headers={**self.headers,'Idempotency-Key':'collision'})
        self.assertEqual(collision.status_code,409)
        for path in self.path.parent.iterdir():
            if path.is_file():
                self.assertNotIn(b'198.51.100.',path.read_bytes())
                self.assertNotIn(b'LAB-01',path.read_bytes())

    def test_conflicting_unmapped_sysmon_field_is_not_silently_deduplicated(self):
        event = make_event(1, 900)
        event['EventData']['Hashes'] = 'SHA256=synthetic-first'
        first = self.client.post('/api/v1/ingest/sysmon', json={'events':[event]}, headers=self.headers)
        self.assertEqual(first.status_code, 200, first.text)
        event['EventData']['Hashes'] = 'SHA256=synthetic-second'
        other = self.client.post('/api/v1/ingest/sysmon', json={'events':[event]}, headers={**self.headers, 'Idempotency-Key':'other'})
        self.assertEqual(other.status_code, 409, other.text)
        self.assertEqual(len(self.client.get('/api/v1/history',headers=self.headers).json()['analyses']), 1)
        self.assertNotIn('synthetic-second', other.text)

    def test_legacy_unversioned_event_fingerprint_fails_closed(self):
        event = make_event(1, 901)
        first = self.client.post('/api/v1/ingest/sysmon', json={'events':[event]}, headers=self.headers)
        self.assertEqual(first.status_code, 200, first.text)
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE stream_events SET fingerprint=?', ('a' * 64,))
        retry = self.client.post('/api/v1/ingest/sysmon', json={'events':[event]}, headers={**self.headers, 'Idempotency-Key':'legacy-retry'})
        self.assertEqual(retry.status_code, 409)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT fingerprint FROM stream_events').fetchone()[0], 'a' * 64)

    def test_inbound_and_late_events_do_not_inflate(self):
        for i,(minute,ip,direction) in enumerate([(2,1,'true'),(3,2,'false'),(0,3,'true'),(1,4,'true')]):
            event=make_event(3,200+i);event['EventData']['UtcTime']=f'2026-11-09 10:0{minute}:00.000'
            event['EventData']['DestinationIp']=f'198.51.100.{ip}';event['EventData']['Initiated']=direction
            response=self.client.post('/api/v1/ingest/sysmon',json={'events':[event]},headers={**self.headers,'Idempotency-Key':f'late-{i}'})
            self.assertEqual(response.status_code,200,response.text)
        data=self.client.get('/api/v1/history',headers=self.headers).json()
        finding=next(d for d in data['detections'] if d['source']=='correlation')
        self.assertEqual(len(finding['event_ids']),3)
        self.assertIn('10:00:00', ' '.join(finding['evidence']))

    def test_expanded_fanout_preserves_first_simulated_approval(self):
        for i in range(3):
            event=make_event(3,300+i);event['EventData']['UtcTime']=f'2026-11-09 10:0{i}:00.000'
            event['EventData']['DestinationIp']=f'198.51.100.{i+1}'
            result=self.client.post('/api/v1/ingest/sysmon',json={'events':[event]},headers={**self.headers,'Idempotency-Key':f'approval-{i}'})
            self.assertEqual(result.status_code,200,result.text)
        before=self.client.get('/api/v1/history',headers=self.headers).json()
        finding=next(d for d in before['detections'] if d['source']=='correlation')
        result=self.client.post(f"/api/v1/detections/{finding['detection_id']}/approval",headers=self.headers,
                                json={'analyst':'analyst-1','rationale':'first review'})
        self.assertEqual(result.status_code,200)
        event=make_event(3,304);event['EventData']['UtcTime']='2026-11-09 10:04:00.000'
        event['EventData']['DestinationIp']='198.51.100.4'
        result=self.client.post('/api/v1/ingest/sysmon',json={'events':[event]},headers={**self.headers,'Idempotency-Key':'approval-next'})
        self.assertEqual(result.status_code,200,result.text)
        after=self.client.get('/api/v1/history',headers=self.headers).json()
        alerts=[d for d in after['detections'] if d['source']=='correlation']
        self.assertEqual(len(alerts),2)
        approved=next(d for d in alerts if d['status']=='approved_for_simulated_response')
        pending=next(d for d in alerts if d['status']=='pending_review')
        self.assertEqual(len(approved['event_ids']),3)
        self.assertEqual(len(pending['event_ids']),4)
        self.assertEqual(approved['approval']['rationale'],'first review')
        self.assertNotIn('approval',pending)

    def test_collector_requires_record_id(self):
        event=make_event();event['System'].pop('EventRecordID')
        result=self.client.post('/api/v1/ingest/sysmon',json={'events':[event]},headers=self.headers)
        self.assertEqual(result.status_code,422)
        self.assertEqual(self.client.get('/api/v1/history',headers=self.headers).json()['analyses'],[])

    def test_concurrent_different_batch_keys_do_not_duplicate_event(self):
        event=make_event()
        def send(index):
            return self.client.post('/api/v1/ingest/sysmon',json={'events':[event]},
                                    headers={**self.headers,'Idempotency-Key':f'parallel-{index}'})
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results=list(pool.map(send,range(4)))
        self.assertTrue(all(r.status_code==200 for r in results),[r.text for r in results])
        self.assertEqual(sum(r.json()['summary']['processed'] for r in results),1)
        snapshot=self.client.get('/api/v1/history',headers=self.headers).json()
        self.assertEqual(sum(len(a['source_events']) for a in snapshot['analyses']),1)

    def test_failure_after_event_insert_rolls_back_and_retries(self):
        with patch.object(SQLiteHistory,'_stream_fanout',side_effect=RuntimeError('private')):
            failed=self.client.post('/api/v1/ingest/sysmon',json=self.body,headers=self.headers)
        self.assertEqual(failed.status_code,503)
        self.assertNotIn('private',failed.text)
        self.assertEqual(self.client.get('/api/v1/history',headers=self.headers).json()['analyses'],[])
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM stream_events').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM collected_batches').fetchone()[0],0)
        retried=self.client.post('/api/v1/ingest/sysmon',json=self.body,headers=self.headers)
        self.assertEqual(retried.status_code,200,retried.text)
        self.assertEqual(retried.json()['summary']['processed'],1)

    def test_process_exit_after_insert_rolls_back_partial_data(self):
        # Child exits during the actual SQLite transaction, before commit.
        api.service.history.list_collectors()
        script = '''import os,sys
from aegis_on.history_store import SQLiteHistory
s=SQLiteHistory(sys.argv[1]); SQLiteHistory._stream_fanout=staticmethod(lambda *args: os._exit(31))
b={'analysis_id':'transient','summary':{'total':1,'processed':1},'source_events':[{'event_id':'ev'}], 'event_refs':[{'event_id':'ev'}], 'attack_model':{'results':[]},'detection_ids':[]}
event={'event_key':'a','fingerprint':'b','host_key':'c','occurred':'2026-01-01T00:00:00+00:00','destination_key':None,'outbound':False,'event_id':'ev','host_display':'masked'}
s.save_analysis(b,[],{'collector_id':'c','batch_id':'b','input_type':'sysmon','digest':'a'*64,'events':[event]})
'''
        child=subprocess.run([sys.executable,'-c',script,str(self.path)],env={**os.environ,'PYTHONPATH':'src'})
        self.assertEqual(child.returncode,31)
        with sqlite3.connect(self.path) as db:
            for table in ('stream_events','collected_batches','analyses','detections'):
                self.assertEqual(db.execute(f'SELECT count(*) FROM {table}').fetchone()[0],0)
        retry=self.client.post('/api/v1/ingest/sysmon',json=self.body,headers=self.headers)
        self.assertEqual(retry.status_code,200,retry.text)

    def test_upgrade_v2_preserves_history_approvals_and_batches(self):
        first=self.client.post('/api/v1/ingest/sysmon',json=self.body,headers=self.headers)
        self.assertEqual(first.status_code,200,first.text)
        before=self.client.get('/api/v1/history',headers=self.headers).json()
        detection=before['detections'][0]['detection_id']
        approval=self.client.post(f'/api/v1/detections/{detection}/approval',headers=self.headers,
                                  json={'analyst':'analyst-1','rationale':'reviewed'})
        self.assertEqual(approval.status_code,200)
        with sqlite3.connect(self.path) as db:
            db.execute('DROP TABLE stream_alert_spans')
            db.execute('DROP INDEX stream_host_event_id')
            db.execute('DROP TABLE auth_correlation_alerts')
            db.execute('DROP TABLE auth_correlation_events')
            db.execute('DROP TABLE auth_correlation_meta')
            db.execute('DROP TABLE stream_alerts')
            db.execute('DROP TABLE stream_events')
            db.execute('PRAGMA user_version=2')
        api.service=DetectionService(SQLiteHistory(self.path))
        after=self.client.get('/api/v1/history',headers=self.headers).json()
        self.assertEqual(after['analyses'][0]['analysis_id'],first.json()['analysis_id'])
        self.assertEqual(next(d for d in after['detections'] if d['detection_id']==detection)['approval']['rationale'],'reviewed')
        replay=self.client.post('/api/v1/ingest/sysmon',json=self.body,headers=self.headers)
        self.assertTrue(replay.json()['replayed'])
        with sqlite3.connect(self.path) as db:self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],5)

    def test_malformed_v1_migration_fails_without_changing_schema(self):
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE analyses (sequence INTEGER PRIMARY KEY, payload TEXT NOT NULL)')
            db.execute('PRAGMA user_version=1')
        os.chmod(self.path, 0o600)
        with self.assertRaises(HistoryError):
            SQLiteHistory(self.path).list_snapshot()
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 1)
            self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='collectors'").fetchone())

if __name__=='__main__':unittest.main()
