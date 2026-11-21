"""Credential transitions use an actual SQLite file and registered identities."""
import concurrent.futures
import os
from pathlib import Path
import sqlite3
from contextlib import closing
import tempfile
import threading
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from aegis_on import api
from aegis_on.auth_sessions import hash_password
from aegis_on.collector_auth import CollectorRegistry, CollectorStateConflict
from aegis_on.history_store import SQLiteHistory
from aegis_on.service import DetectionService
from test_sysmon_api import make_event


class CollectorLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'history.sqlite3'
        previous=api.service; self.addCleanup(setattr,api,'service',previous)
        api.service=DetectionService(SQLiteHistory(self.path))
        env=patch.dict(os.environ,{'AEGIS_HISTORY_DB':str(self.path),'AEGIS_AUTH_DB':str(self.path)+'.auth',
            'AEGIS_LOGIN_USERNAME':'analyst','AEGIS_LOGIN_PASSWORD_HASH':hash_password('synthetic-password-123'),
            'AEGIS_ANALYST_NAME':'analyst','AEGIS_API_TOKEN':'legacy-synthetic-token',
            'AEGIS_ALLOW_LEGACY_COLLECTOR_TOKEN':'1'},clear=False)
        env.start();self.addCleanup(env.stop)
        api._login_attempts.clear();api._session_config.cache_clear()
        self.client=TestClient(api.app,base_url='https://testserver');self.addCleanup(self.client.close)
        self.assertEqual(self.client.post('/api/v1/login',json={'username':'analyst','password':'synthetic-password-123'}).status_code,200)
        self.csrf=self.client.get('/api/v1/session').json()['csrf_token']
        self.admin={'X-CSRF-Token':self.csrf}

    def register(self,name):
        r=self.client.post('/api/v1/collectors/register',json={'collector_id':name},headers=self.admin)
        self.assertEqual(r.status_code,200,r.text);self.assertEqual(r.headers['cache-control'],'no-store')
        return r.json()['credential']

    @staticmethod
    def headers(name,secret,batch='batch'):
        return {'X-Collector-ID':name,'Authorization':'Bearer '+secret,'Idempotency-Key':batch}

    def heartbeat(self,name,secret,state='running',code=None):
        return self.client.post('/api/v1/collectors/'+name+'/heartbeat',json={'state':state,'error_code':code},headers=self.headers(name,secret))

    def test_two_collectors_revoke_reissue_replay_and_restart(self):
        old=self.register('pc-a');other=self.register('pc-b')
        event=make_event(1,900);h=self.headers('pc-a',old,'a1')
        first=self.client.post('/api/v1/ingest/sysmon',json={'events':[event]},headers=h)
        self.assertEqual(first.status_code,200,first.text)
        first_history=self.client.get('/api/v1/history').json()
        self.assertTrue(first_history['detections'])
        detection_id=first_history['detections'][0]['detection_id']
        approval=self.client.post('/api/v1/detections/'+detection_id+'/approval',
                                  json={'analyst':'analyst','rationale':'synthetic review'},headers=self.admin)
        self.assertEqual(approval.status_code,200,approval.text)
        self.assertTrue(approval.json()['simulation_only'])
        event2=make_event(3,901);h2=self.headers('pc-b',other,'b1')
        self.assertEqual(self.client.post('/api/v1/ingest/sysmon',json={'events':[event2]},headers=h2).status_code,200)
        self.assertEqual(self.heartbeat('pc-a',old,'error','read_error').status_code,200)
        self.assertEqual(self.heartbeat('pc-a',old).status_code,200)
        state=next(x for x in self.client.get('/api/v1/collectors').json()['collectors'] if x['collector_id']=='pc-a')
        self.assertEqual(state['reported_state'],'running');self.assertEqual(state['last_error_code'],'read_error');self.assertTrue(state['last_error_at'])
        # Reproduce the legacy bypass: registered IDs never accept the shared token.
        self.assertEqual(self.heartbeat('pc-a','legacy-synthetic-token').status_code,401)
        self.assertEqual(self.heartbeat('unregistered-legacy','legacy-synthetic-token').status_code,200)
        self.assertEqual(self.client.post('/api/v1/collectors/pc-a/reissue',headers=self.admin).status_code,409)
        self.assertEqual(self.client.post('/api/v1/collectors/pc-a/revoke',headers=self.admin).status_code,200)
        for invalid in (old,'legacy-synthetic-token'):
            self.assertEqual(self.heartbeat('pc-a',invalid).status_code,401)
            self.assertEqual(self.client.post('/api/v1/ingest/sysmon',json={'events':[event]},headers=self.headers('pc-a',invalid,'a2')).status_code,401)
        self.assertEqual(self.heartbeat('pc-b',other).status_code,200)
        self.assertEqual(self.client.post('/api/v1/collectors/pc-a/revoke',headers=self.admin).status_code,409)
        r=self.client.post('/api/v1/collectors/pc-a/reissue',headers=self.admin)
        self.assertEqual(r.status_code,200,r.text);new=r.json()['credential'];self.assertNotEqual(old,new)
        self.assertEqual(r.headers['cache-control'],'no-store')
        self.assertEqual(self.heartbeat('pc-a',old).status_code,401)
        self.assertEqual(self.heartbeat('pc-a','legacy-synthetic-token').status_code,401)
        replay=self.client.post('/api/v1/ingest/sysmon',json={'events':[event]},headers=self.headers('pc-a',new,'a1'))
        self.assertEqual(replay.status_code,200);self.assertTrue(replay.json()['replayed'])
        duplicate=self.client.post('/api/v1/ingest/sysmon',json={'events':[event]},headers=self.headers('pc-a',new,'a2'))
        self.assertEqual(duplicate.status_code,200,duplicate.text);self.assertEqual(duplicate.json()['summary']['duplicate'],1)
        self.assertEqual(self.heartbeat('pc-a',new).status_code,200)
        api.service=DetectionService(SQLiteHistory(self.path))
        self.assertEqual(self.heartbeat('pc-a',new).status_code,200)
        self.assertEqual(self.heartbeat('pc-a',old).status_code,401)
        data=self.client.get('/api/v1/history').json();self.assertEqual(sum(len(x.get('source_events',[])) for x in data['analyses']),2)
        saved=next(d for d in data['detections'] if d['detection_id']==detection_id)
        self.assertEqual(saved['status'],'approved_for_simulated_response')
        self.assertEqual(saved['approval']['rationale'],'synthetic review')
        groups=self.client.get('/api/v1/endpoints').json()['endpoints'];self.assertEqual(len(groups),2)
        self.assertEqual({g['collector_id'] for g in groups},{'pc-a','pc-b'})
        self.assertEqual(len({g['endpoint_id'] for g in groups}),2)
        for path in self.path.parent.iterdir():
            if path.is_file():
                for secret in (old,other,new): self.assertNotIn(secret.encode(),path.read_bytes())
        self.assertNotIn(old,self.client.get('/api/v1/collectors').text)
        self.assertNotIn(new,self.client.get('/api/v1/history').text)

    def test_management_requires_browser_session_and_csrf(self):
        secret=self.register('protected')
        for suffix in ('revoke','reissue'):
            url='/api/v1/collectors/protected/'+suffix
            self.assertEqual(self.client.post(url).status_code,403)
            self.assertEqual(self.client.post(url,headers={**self.admin,'Origin':'https://evil.invalid'}).status_code,403)
            with TestClient(api.app,base_url='https://testserver') as other:
                self.assertEqual(other.post(url).status_code,401)
                self.assertEqual(other.post(url,headers={'Authorization':'Bearer '+secret}).status_code,401)
                self.assertEqual(other.post(url,headers={'Authorization':'Bearer legacy-synthetic-token'}).status_code,403)
        self.assertEqual(self.client.post('/api/v1/collectors/missing/revoke',headers=self.admin).status_code,404)
        self.assertEqual(self.heartbeat('protected',secret).status_code,200)

    def test_simultaneous_reissue_only_one_credential_is_live(self):
        registry=CollectorRegistry(SQLiteHistory(self.path));old=registry.register('concurrent');registry.revoke('concurrent')
        def issue(_):
            try:return CollectorRegistry(SQLiteHistory(self.path)).reissue('concurrent')
            except CollectorStateConflict:return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool: results=list(pool.map(issue,range(4)))
        issued=[v for v in results if v]
        self.assertEqual(len(issued),1);self.assertTrue(registry.authenticate('concurrent',issued[0]));self.assertFalse(registry.authenticate('concurrent',old))

    def test_existing_registry_upgrade_preserves_active_credential(self):
        registry=CollectorRegistry(SQLiteHistory(self.path));old=registry.register('existing')
        with closing(sqlite3.connect(self.path)) as db, db:db.execute('DROP TABLE collector_credential_changes')
        reopened=CollectorRegistry(SQLiteHistory(self.path));self.assertTrue(reopened.authenticate('existing',old))
        self.assertEqual(reopened.list_collectors()[0]['credential_state'],'active')
        reopened.revoke('existing');self.assertFalse(reopened.authorize('existing','legacy-synthetic-token','legacy-synthetic-token'))

    def test_request_authenticated_before_revocation_can_finish_after(self):
        secret=self.register('inflight')
        started=threading.Event();release=threading.Event()
        original=api.service.history.heartbeat
        def delayed(*args):
            started.set()
            if not release.wait(5): raise RuntimeError('test timeout')
            return original(*args)
        with patch.object(api.service.history,'heartbeat',side_effect=delayed):
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future=pool.submit(self.heartbeat,'inflight',secret)
                try:
                    self.assertTrue(started.wait(5))
                    self.assertEqual(self.client.post('/api/v1/collectors/inflight/revoke',headers=self.admin).status_code,200)
                finally:
                    release.set()
                self.assertEqual(future.result().status_code,200)
        self.assertEqual(self.heartbeat('inflight',secret).status_code,401)
