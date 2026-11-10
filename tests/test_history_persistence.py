import concurrent.futures
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from fastapi.testclient import TestClient
from aegis_on import api
from aegis_on.attack_model import AttackModel
from aegis_on.history_store import SQLiteHistory, HistoryError
from aegis_on.pii import PIIDetector, Span
from aegis_on.service import DetectionService
from test_sysmon_api import make_event
from test_pii_verified_hosts import SurnameModel


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name,'data','history.sqlite3')
        self.old=(api.service,api.attack_model,api.pii_detector)
        self.addCleanup(self.restore)
        api.service=DetectionService(SQLiteHistory(self.path));api.attack_model=AttackModel();api.pii_detector=PIIDetector()
        self.env=patch.dict('os.environ',{'AEGIS_API_TOKEN':'token-example-123','AEGIS_ANALYST_NAME':'analyst-1'},clear=False)
        self.env.start();self.addCleanup(self.env.stop)
        self.client=TestClient(api.app);self.addCleanup(self.client.close)
        self.headers={'Authorization':'Bearer token-example-123'}

    def restore(self): api.service,api.attack_model,api.pii_detector=self.old

    def create(self):
        event=make_event(1,123)
        event['EventData']['User']='synthetic.user@example.invalid'
        event['EventData']['CommandLine']='curl https://example.invalid/tool --password=FakePassword123 token-example-123'
        unsupported=make_event(2,124)
        r=self.client.post('/api/v1/sysmon/analyze',json={'events':[unsupported,event]},headers=self.headers)
        self.assertEqual(r.status_code,200,r.text)
        return r.json()

    def test_persist_restart_link_privacy_and_approval(self):
        a=self.create();self.assertEqual(a['summary']['processed'],1)
        det=a['detections'][0]; url='/api/v1/detections/'+det['detection_id']+'/approval'
        r=self.client.post(url,headers=self.headers,json={'analyst':'analyst-1','rationale':'synthetic.user@example.invalid password=FakePassword123 token-example-123'})
        self.assertEqual(r.status_code,200,r.text)
        first=r.json(); self.assertTrue(first['simulation_only'])
        api.service=DetectionService(SQLiteHistory(self.path))
        self.assertEqual(self.client.get('/api/v1/history').status_code,401)
        h=self.client.get('/api/v1/history',headers=self.headers);self.assertEqual(h.status_code,200)
        batch=h.json()['analyses'][0]; detection=next(d for d in h.json()['detections'] if d['detection_id']==det['detection_id'])
        self.assertEqual(batch['analysis_id'],a['analysis_id'])
        self.assertEqual(batch['source_events'][0]['input_index'],1)
        self.assertEqual(batch['event_refs'][0]['input_index'],1)
        self.assertIn(batch['source_events'][0]['event_id'],detection['event_ids'])
        self.assertEqual(detection['approval']['simulation_only'],True)
        self.assertEqual(detection['status'],'approved_for_simulated_response')
        again=self.client.post(url,headers=self.headers,json={'analyst':'analyst-1','rationale':'later'})
        self.assertEqual(again.json(),first)
        self.assertEqual(len([x for x in detection['evidence'] if x.startswith('approved locally by')]),1)
        for file in self.path.parent.iterdir():
            if file.is_file():
                raw=file.read_bytes()
                for secret in (b'synthetic.user@example.invalid',b'FakePassword123',b'token-example-123',b'https://example.invalid/tool'):
                    self.assertNotIn(secret,raw)
        for secret in ('synthetic.user@example.invalid','FakePassword123','token-example-123','https://example.invalid/tool'):
            self.assertNotIn(secret,h.text)

    def test_storage_failure_not_success_and_no_partial_history(self):
        with patch.object(api.service.history,'save_analysis',side_effect=HistoryError('private')):
            response=self.client.post('/api/v1/analyze',json={'events':[{'timestamp':'2026-01-01T00:00:00Z','host':'lab','user':'u','process':'curl','command_line':'curl https://example.invalid','event_id':'abc'}]},headers=self.headers)
        self.assertEqual(response.status_code,503);self.assertNotIn('private',response.text)
        h=self.client.get('/api/v1/history',headers=self.headers).json()
        self.assertEqual(h['analyses'],[]);self.assertEqual(h['detections'],[])

    def test_empty_history_and_legacy_identifier_privacy(self):
        self.assertEqual(self.client.get('/api/v1/history').status_code, 401)
        self.assertEqual(self.client.get('/api/v1/history', headers=self.headers).json(), {'analyses': [], 'detections': []})
        event = {'timestamp':'2026-01-01T00:00:00Z', 'host':'PrivateWorkstationCanary',
                 'user':'person', 'process':'curl', 'command_line':'curl https://example.invalid',
                 'event_id':'PrivateEventCanary'}
        result = self.client.post('/api/v1/analyze', json={'events':[event]}, headers=self.headers)
        self.assertEqual(result.status_code, 200, result.text)
        history = self.client.get('/api/v1/history', headers=self.headers)
        self.assertNotIn('PrivateWorkstationCanary', history.text)
        self.assertNotIn('PrivateEventCanary', history.text)
        row = history.json()['analyses'][0]
        self.assertIn(row['event_refs'][0]['event_id'], history.json()['detections'][0]['event_ids'])
        for secret in (b'PrivateWorkstationCanary', b'PrivateEventCanary'):
            self.assertNotIn(secret, self.path.read_bytes())

    @unittest.skipUnless(os.name == 'posix', 'POSIX permissions test')
    def test_private_database_and_reject_insecure_existing_file(self):
        self.client.get('/api/v1/history', headers=self.headers)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        os.chmod(self.path, 0o644)
        self.assertEqual(self.client.get('/api/v1/history', headers=self.headers).status_code, 503)

    def test_public_host_exception_respects_revocation_after_restart(self):
        api.pii_detector = PIIDetector(SurnameModel())
        with patch.dict('os.environ', {'AEGIS_PII_VERIFIED_PUBLIC_HOSTS': json.dumps(['김치서비스'], ensure_ascii=False)}):
            event = {'timestamp':'2026-01-01T00:00:00Z', 'host':'김치서비스', 'user':'김',
                     'process':'curl', 'command_line':'curl /Users/김', 'event_id':'safe-event'}
            result = self.client.post('/api/v1/analyze', json={'events':[event]}, headers=self.headers)
            self.assertEqual(result.status_code, 200, result.text)
            api.service = DetectionService(SQLiteHistory(self.path))
            self.assertEqual(self.client.get('/api/v1/history', headers=self.headers).json()['detections'][0]['host'], '김치서비스')
            with patch.dict('os.environ', {'AEGIS_PII_VERIFIED_PUBLIC_HOSTS': '{invalid'}):
                self.assertNotEqual(self.client.get('/api/v1/history', headers=self.headers).json()['detections'][0]['host'], '김치서비스')

    def test_corrupt_and_unsupported_version_fail_closed(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_bytes(b'not-a-sqlite-db')
        r=self.client.get('/api/v1/history',headers=self.headers)
        self.assertEqual(r.status_code,503);self.assertNotIn(str(self.path),r.text)
        self.path.unlink()
        with sqlite3.connect(self.path) as conn: conn.execute('PRAGMA user_version=99')
        self.assertEqual(self.client.get('/api/v1/history',headers=self.headers).status_code,503)

    def test_database_transaction_rolls_back_duplicate_detection(self):
        store=SQLiteHistory(self.path)
        with self.assertRaises(HistoryError): store.save_analysis({'analysis_id':'a'},[{'detection_id':'same','evidence':[]},{'detection_id':'same','evidence':[]}])
        self.assertEqual(store.list_analyses(),[]);self.assertEqual(store.list_detections(),[])

    def test_missing_or_replaced_live_database_fails_closed(self):
        self.create()
        self.path.unlink()
        self.assertEqual(self.client.get('/api/v1/history', headers=self.headers).status_code, 503)
        self.assertFalse(self.path.exists())


    def test_truncated_database_is_not_reinitialized(self):
        self.create()
        self.path.write_bytes(b'')
        self.assertEqual(self.client.get('/api/v1/history', headers=self.headers).status_code, 503)
        self.assertEqual(self.path.stat().st_size, 0)
        api.service = DetectionService(SQLiteHistory(self.path))
        self.assertEqual(self.client.get('/api/v1/history', headers=self.headers).status_code, 503)
        self.assertEqual(self.path.stat().st_size, 0)

    def test_transient_initial_connection_failure_can_retry_without_deleting_file(self):
        store = SQLiteHistory(self.path)
        with patch('sqlite3.connect', side_effect=sqlite3.OperationalError('temporary')):
            with self.assertRaises(HistoryError):
                store.list_snapshot()
        self.assertTrue(self.path.exists())
        original_stat = self.path.stat()
        self.assertEqual(store.list_snapshot(), ([], []))
        self.assertEqual(self.path.stat().st_ino, original_stat.st_ino)

    def test_preexisting_empty_database_is_not_claimed_by_new_instance(self):
        self.path.parent.mkdir(parents=True)
        self.path.touch(mode=0o600)
        with self.assertRaises(HistoryError):
            SQLiteHistory(self.path).list_snapshot()
        self.assertEqual(self.path.stat().st_size, 0)

    def test_initialization_is_serialized_and_truncation_stays_an_error(self):
        store = SQLiteHistory(self.path)
        entered, release = threading.Event(), threading.Event()
        original_connect = sqlite3.connect
        calls = 0
        def delayed_connect(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                entered.set()
                if not release.wait(5):
                    raise RuntimeError('test timed out')
            return original_connect(*args, **kwargs)
        try:
            with patch('sqlite3.connect', side_effect=delayed_connect):
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    first = pool.submit(store.list_snapshot)
                    self.assertTrue(entered.wait(5))
                    second = pool.submit(store.save_analysis, {'analysis_id':'a'}, [{'detection_id':'d', 'evidence':[]}])
                    self.assertFalse(second.done())
                    release.set()
                    self.assertEqual(first.result(timeout=5), ([], []))
                    second.result(timeout=5)
        finally:
            release.set()
        self.path.write_bytes(b'')
        with self.assertRaises(HistoryError):
            store.list_snapshot()

    def test_locked_database_returns_503_without_modifying_history(self):
        result = self.create()
        api.service.history.timeout = 0.05
        conn = sqlite3.connect(self.path, isolation_level=None)
        try:
            conn.execute('BEGIN EXCLUSIVE')
            response = self.client.get('/api/v1/history', headers=self.headers)
            self.assertEqual(response.status_code, 503)
        finally:
            conn.rollback()
            conn.close()
        history = self.client.get('/api/v1/history', headers=self.headers).json()
        self.assertEqual(history['analyses'][0]['analysis_id'], result['analysis_id'])

    def test_killed_writer_rolls_back_incomplete_batch(self):
        result = self.create()
        script = '''import sqlite3, sys
conn = sqlite3.connect(sys.argv[1], isolation_level=None)
conn.execute("BEGIN IMMEDIATE")
conn.execute("INSERT INTO analyses(payload) VALUES (?)", ('{"analysis_id":"incomplete"}',))
print("inserted", flush=True)
sys.stdin.read()
'''
        process = subprocess.Popen([sys.executable, '-c', script, str(self.path)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(), 'inserted')
            process.kill()
            process.wait(timeout=5)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdin.close(); process.stdout.close(); process.stderr.close()
        history = self.client.get('/api/v1/history', headers=self.headers).json()
        self.assertEqual([a['analysis_id'] for a in history['analyses']], [result['analysis_id']])
        self.assertTrue(history['detections'])

    def test_secret_key_is_not_broken_by_pii_mask_before_redaction(self):
        class PartialKeyModel:
            def find(self, text):
                start = text.find('password=')
                return [Span(start, start + 4, 'USERNAME', 'model')] if start >= 0 else []
        api.pii_detector = PIIDetector(PartialKeyModel())
        result = self.create()
        detection = result['detections'][0]['detection_id']
        response = self.client.post('/api/v1/detections/' + detection + '/approval', headers=self.headers,
                                    json={'analyst':'analyst-1', 'rationale':'password=FAKE_SECRET_8675309'})
        self.assertEqual(response.status_code, 200)
        history = self.client.get('/api/v1/history', headers=self.headers)
        for text in (response.text, history.text, self.path.read_bytes().decode('latin1')):
            self.assertNotIn('FAKE_SECRET_8675309', text)

    def test_snapshot_never_separates_batch_and_detections_during_writes(self):
        store = SQLiteHistory(self.path)
        store.list_snapshot()
        def write():
            for i in range(15):
                store.save_analysis({'analysis_id':str(i),'detection_ids':[str(i)]},
                                    [{'detection_id':str(i),'evidence':[]}])
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            writer = pool.submit(write)
            while not writer.done():
                batches, detections = store.list_snapshot()
                self.assertEqual({i for b in batches for i in b['detection_ids']},
                                 {d['detection_id'] for d in detections})
            writer.result()
        batches, detections = store.list_snapshot()
        self.assertEqual(len(batches), 15)
        self.assertEqual(len(detections), 15)

    def test_concurrent_approvals_across_processes(self):
        a=self.create();det=a['detections'][0]['detection_id']
        code='import json,sys; from aegis_on.history_store import SQLiteHistory; print(json.dumps(SQLiteHistory(sys.argv[1]).approve(sys.argv[2],"analyst-1",sys.argv[3]),sort_keys=True))'
        def invoke(i):
            return subprocess.run([sys.executable,'-c',code,str(self.path),det,'reason-'+str(i)],capture_output=True,text=True,check=True,env={**os.environ,'PYTHONPATH':'src'}).stdout
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool: outputs=list(pool.map(invoke,range(6)))
        self.assertTrue(all(o==outputs[0] for o in outputs))
        row=json.loads(outputs[0]);self.assertEqual(len([x for x in row['evidence'] if x.startswith('approved locally by ')]),1)
        self.assertTrue(row['approval']['rationale'].startswith('reason-'))

    def test_real_server_restart(self):
        env={**os.environ,'PYTHONPATH':'src','AEGIS_HISTORY_DB':str(self.path),'AEGIS_API_TOKEN':'local-test','AEGIS_ANALYST_NAME':'analyst-1'}
        with socket.socket() as s:
            s.bind(('127.0.0.1',0)); port=s.getsockname()[1]
        root=f'http://127.0.0.1:{port}'
        def launch():
            proc=subprocess.Popen([sys.executable,'-m','uvicorn','aegis_on.api:app','--host','127.0.0.1','--port',str(port)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            for _ in range(120):
                try:
                    with urllib.request.urlopen(root+'/api/v1/health',timeout=.2): return proc
                except (OSError,urllib.error.URLError):
                    if proc.poll() is not None: self.fail('server failed to start')
                    time.sleep(.05)
            proc.terminate();proc.wait(timeout=5);self.fail('server startup timeout')
        def request(path,body=None):
            data=json.dumps(body).encode() if body is not None else None
            req=urllib.request.Request(root+path,data=data,headers={'Authorization':'Bearer local-test','Content-Type':'application/json'})
            with urllib.request.urlopen(req,timeout=5) as response:return json.load(response)
        first=launch()
        try:
            e={'timestamp':'2026-01-01T00:00:00Z','host':'lab','user':'analyst','process':'curl','command_line':'curl https://example.invalid','event_id':'synthetic-event'}
            a=request('/api/v1/analyze',{'events':[e]});det=a['detections'][0]['detection_id']
            approved=request('/api/v1/detections/'+det+'/approval',{'analyst':'analyst-1','rationale':'first'})
        finally: first.terminate();first.wait(timeout=5)
        second=launch()
        try:
            h=request('/api/v1/history');self.assertEqual(h['analyses'][0]['analysis_id'],a['analysis_id'])
            self.assertEqual(next(d for d in h['detections'] if d['detection_id']==det)['approval']['rationale'],'first')
            self.assertTrue(approved['simulation_only'])
        finally: second.terminate();second.wait(timeout=5)

if __name__=='__main__': unittest.main()
