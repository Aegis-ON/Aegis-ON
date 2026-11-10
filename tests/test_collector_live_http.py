"""Loopback HTTP test with real server restart and synthetic credentials/events."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import httpx
from aegis_on.auth_sessions import hash_password
from test_sysmon_api import make_event

class CollectorLiveHttpTests(unittest.TestCase):
    def test_two_collectors_lifecycle_survives_actual_server_restart(self):
        with tempfile.TemporaryDirectory() as temp:
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',0)); port=listener.getsockname()[1]
            env={**os.environ,'PYTHONPATH':'src','AEGIS_HISTORY_DB':str(Path(temp)/'history.sqlite3'),
                'AEGIS_AUTH_DB':str(Path(temp)/'sessions.sqlite3'),'AEGIS_LOGIN_USERNAME':'synthetic',
                'AEGIS_LOGIN_PASSWORD_HASH':hash_password('synthetic-password-123'),
                'AEGIS_PII_MODEL_DIR':'','AEGIS_ATTACK_MODEL_DIR':'',
                'AEGIS_ANALYST_NAME':'synthetic','AEGIS_API_TOKEN':'legacy-synthetic-token',
                'AEGIS_ALLOW_LEGACY_COLLECTOR_TOKEN':'1'}
            url=f'http://127.0.0.1:{port}'
            process=None
            def start():
                p=subprocess.Popen([sys.executable,'-m','uvicorn','aegis_on.api:app','--host','127.0.0.1','--port',str(port),'--no-access-log'],
                                   env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    if p.poll() is not None: self.fail('server exited before startup')
                    try:
                        if httpx.get(url+'/api/v1/health',timeout=.5,trust_env=False).status_code==200:return p
                    except httpx.HTTPError:pass
                    time.sleep(.1)
                p.terminate();p.wait(timeout=5);self.fail('server startup timed out')
            def stop(p):
                if p and p.poll() is None:
                    p.terminate()
                    try:p.wait(timeout=5)
                    except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
            def headers(name,token,batch):return {'Authorization':'Bearer '+token,'X-Collector-ID':name,'Idempotency-Key':batch}
            try:
                process=start()
                with httpx.Client(base_url=url,timeout=5,trust_env=False) as client:
                    self.assertEqual(client.post('/api/v1/login',json={'username':'synthetic','password':'synthetic-password-123'}).status_code,200)
                    csrf=client.get('/api/v1/session').json()['csrf_token'];auth={'X-CSRF-Token':csrf}
                    tokens={name:client.post('/api/v1/collectors/register',json={'collector_id':name},headers=auth).json()['credential'] for name in ('one','two')}
                    for idx,name in enumerate(tokens):
                        r=client.post('/api/v1/ingest/sysmon',json={'events':[make_event(1,910+idx)]},headers=headers(name,tokens[name],'first'))
                        self.assertEqual(r.status_code,200,r.text)
                    self.assertEqual(client.post('/api/v1/collectors/one/revoke',headers=auth).status_code,200)
                    for path,body in [('/api/v1/collectors/one/heartbeat',{'state':'running'}),('/api/v1/ingest/sysmon',{'events':[make_event(1,910)]})]:
                        for token in (tokens['one'],'legacy-synthetic-token'):
                            self.assertEqual(client.post(path,json=body,headers=headers('one',token,'second')).status_code,401)
                    self.assertEqual(client.post('/api/v1/collectors/two/heartbeat',json={'state':'running'},headers=headers('two',tokens['two'],'h')).status_code,200)
                    r=client.post('/api/v1/collectors/one/reissue',headers=auth);self.assertEqual(r.status_code,200);new=r.json()['credential']
                    self.assertEqual(client.post('/api/v1/collectors/one/heartbeat',json={'state':'running'},headers=headers('one',tokens['one'],'h')).status_code,401)
                    replay=client.post('/api/v1/ingest/sysmon',json={'events':[make_event(1,910)]},headers=headers('one',new,'next'))
                    self.assertEqual(replay.status_code,200);self.assertEqual(replay.json()['summary']['duplicate'],1)
                    stop(process);process=start()
                    self.assertEqual(client.get('/api/v1/history').status_code,200)
                    self.assertEqual(client.post('/api/v1/collectors/one/heartbeat',json={'state':'running'},headers=headers('one',new,'h')).status_code,200)
                    self.assertEqual(client.post('/api/v1/collectors/one/heartbeat',json={'state':'running'},headers=headers('one',tokens['one'],'h')).status_code,401)
                    data=client.get('/api/v1/history').json()
                    self.assertEqual(sum(len(a.get('source_events',[])) for a in data['analyses']),2)
                    groups=client.get('/api/v1/endpoints').json()['endpoints'];self.assertEqual({g['collector_id'] for g in groups},{'one','two'})
            finally:stop(process)
