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
        env = patch.dict('os.environ', {'AEGIS_API_TOKEN':'synthetic-token', 'AEGIS_ANALYST_NAME':'analyst-1'}, clear=False)
        env.start(); self.addCleanup(env.stop)
        self.client = TestClient(api.app); self.addCleanup(self.client.close)
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
        with sqlite3.connect(self.path) as db:self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],2)

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
