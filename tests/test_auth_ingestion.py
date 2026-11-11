import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from aegis_on import api
from aegis_on.attack_model import AttackModel
from aegis_on.history_store import SQLiteHistory
from aegis_on.pii import PIIDetector
from aegis_on.service import DetectionService


def test_auth_pipeline_replay_privacy_and_restart():
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / 'history.sqlite3'
        env = {'AEGIS_API_TOKEN': 'synthetic-token', 'AEGIS_ANALYST_NAME': 'analyst', 'AEGIS_ALLOW_LEGACY_COLLECTOR_TOKEN': '1'}
        events = [{'event_id': f'id-{i}', 'timestamp': f'2026-01-01T00:0{i}:00Z', 'host': 'auth-server',
                   'account': 'fixture-account', 'source_ip': '192.0.2.15',
                   'outcome': 'success' if i == 3 else 'failure'} for i in range(4)]
        headers = {'Authorization': 'Bearer synthetic-token', 'X-Collector-ID': 'auth-source', 'Idempotency-Key': 'batch-1'}
        with patch.dict('os.environ', env), patch.object(api, 'service', DetectionService(SQLiteHistory(path))), \
             patch.object(api, 'pii_detector', PIIDetector()), patch.object(api, 'attack_model', AttackModel()):
            with TestClient(api.app, base_url='https://testserver') as client:
                assert client.post('/api/v1/ingest/auth', json={'events': events}).status_code == 401
                first = client.post('/api/v1/ingest/auth', json={'events': events}, headers=headers)
                assert first.status_code == 200, first.text
                assert not first.json()['replayed']
                api.service = DetectionService(SQLiteHistory(path))
                again = client.post('/api/v1/ingest/auth', json={'events': events}, headers=headers)
                assert again.json()['replayed']
                history = client.get('/api/v1/history', headers=headers).json()
                batch, detection = history['analyses'][0], history['detections'][0]
                assert batch['input_type'] == 'auth' and batch['received_at']
                assert batch['attack_model']['state'] == 'disabled' and not batch['attack_model']['results']
                assert detection['source'] == 'correlation' and len(detection['event_ids']) == 4
                assert set(detection['event_ids']) == {e['event_id'] for e in batch['source_events']}
                assert [e['outcome'] for e in batch['source_events']] == ['failure'] * 3 + ['success']
                endpoints = client.get('/api/v1/endpoints', headers=headers).json()['endpoints']
                assert len(endpoints) == 1 and endpoints[0]['event_count'] == 4
                detail = client.get('/api/v1/endpoints/' + endpoints[0]['endpoint_id'], headers=headers).json()
                assert detail['detections'][0]['detection_id'] == detection['detection_id']
                duplicate = client.post('/api/v1/ingest/auth', json={'events': events}, headers={**headers, 'Idempotency-Key': 'batch-2'})
                assert duplicate.status_code == 200 and duplicate.json()['summary']['duplicate'] == 4
                assert len(client.get('/api/v1/history', headers=headers).json()['detections']) == 1
                for secret in ('synthetic-token', 'fixture-account', 'auth-server', '192.0.2.15'):
                    assert secret not in json.dumps(history)
                    assert secret.encode() not in path.read_bytes()
                with_secret = [{**events[0], 'cookie': 'session=private'}]
                result = client.post('/api/v1/ingest/auth', json={'events': with_secret}, headers={**headers, 'Idempotency-Key': 'bad'})
                assert result.status_code == 422 and 'session=private' not in result.text
                changed = [{**events[0], 'outcome': 'success'}]
                collision = client.post('/api/v1/ingest/auth', json={'events': changed}, headers={**headers, 'Idempotency-Key': 'collision'})
                assert collision.status_code == 409


def test_auth_correlation_does_not_join_distinct_accounts_or_batches():
    from aegis_on.auth_log import correlate_auth, normalize_auth
    base = {'host': 'host', 'account': 'account', 'source_ip': '192.0.2.1'}
    records = [{**base, 'event_id': str(i), 'timestamp': f'2026-01-01T00:0{i}:00Z',
                'outcome': 'failure' if i < 3 else 'success'} for i in range(4)]
    separate = [*records[:3], {**records[3], 'account': 'other'}]
    assert correlate_auth(normalize_auth({'events': separate}, 'collector')[0]) == []
    assert correlate_auth(normalize_auth({'events': records[:3]}, 'collector')[0]) == []
    assert correlate_auth(normalize_auth({'events': records[3:]}, 'collector')[0]) == []


def test_equal_time_does_not_invent_order_and_endpoint_view():
    from aegis_on.auth_log import correlate_auth, normalize_auth
    from aegis_on.endpoint_views import build_endpoint_groups
    base = {'host': 'host', 'account': 'account', 'source_ip': '192.0.2.1', 'timestamp': '2026-01-01T00:00:00Z'}
    records = [{**base, 'event_id': str(i), 'outcome': 'failure' if i < 3 else 'success'} for i in range(4)]
    events, _ = normalize_auth({'events': records}, 'collector')
    assert correlate_auth(events) == []
    sources = [{k: v for k, v in e.items() if k != 'group'} for e in events]
    groups = build_endpoint_groups([{'analysis_id': 'a', 'input_type': 'auth', 'source_events': sources}], [])
    assert len(groups) == 1 and groups[0]['event_count'] == 4


def test_auth_mixed_replay_is_rejected_without_partial_commit():
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / 'history.sqlite3'
        env = {'AEGIS_API_TOKEN': 'synthetic-token', 'AEGIS_ANALYST_NAME': 'analyst', 'AEGIS_ALLOW_LEGACY_COLLECTOR_TOKEN': '1'}
        headers = {'Authorization': 'Bearer synthetic-token', 'X-Collector-ID': 'auth-source', 'Idempotency-Key': 'first'}
        base = {'host': 'host', 'account': 'account', 'source_ip': '192.0.2.1'}
        records = [{**base, 'event_id': str(i), 'timestamp': f'2026-01-01T00:0{i}:00Z',
                    'outcome': 'failure' if i < 3 else 'success'} for i in range(4)]
        with patch.dict('os.environ', env), patch.object(api, 'service', DetectionService(SQLiteHistory(path))):
            with TestClient(api.app, base_url='https://testserver') as client:
                assert client.post('/api/v1/ingest/auth', json={'events': records[:3]}, headers=headers).status_code == 200
                mixed = client.post('/api/v1/ingest/auth', json={'events': records}, headers={**headers, 'Idempotency-Key': 'second'})
                assert mixed.status_code == 409
                history = client.get('/api/v1/history', headers=headers).json()
                assert len(history['analyses']) == 1 and history['detections'] == []
                retry = client.post('/api/v1/ingest/auth', json={'events': records[3:]}, headers={**headers, 'Idempotency-Key': 'third'})
                assert retry.status_code == 200
                after = client.get('/api/v1/history', headers=headers).json()
                assert len(after['analyses']) == 2 and after['detections'] == []


def test_auth_event_visible_in_console_dom():
    import shutil
    import subprocess
    if not shutil.which('node'):
        return
    source = {'timestamp': '2026-01-01T00:00:00+00:00', 'event_id': 'auth-demo', 'host': '[HOST:abc]',
              'log_source': 'auth-normalized', 'outcome': 'failure'}
    data = {'analyses': [{'analysis_id': 'batch', 'received_at': '2026-01-01T00:01:00+00:00',
                          'source_events': [source], 'detection_ids': []}], 'detections': []}
    harness = r'''
const assert=require('assert'),vm=require('vm'),fs=require('fs');
class E{constructor(t='div'){this.tag=t;this.children=[];this._text='';this.value='';this.style={};this.classList={add(){}};}set textContent(x){this._text=String(x)}get textContent(){return this._text+this.children.map(x=>x.textContent).join('')}append(...xs){this.children.push(...xs)}addEventListener(){}setAttribute(){}replaceChildren(...xs){this.children=xs;this._text=''}}
const els=Object.fromEntries(['#kicker','#title','#subtitle','#status','#view','#load'].map(x=>[x,new E()]));
const document={querySelector:q=>els[q]||null,createElement:t=>new E(t)},window={},location={pathname:'/console/events'};
const data=JSON.parse(fs.readFileSync(0,'utf8'));
const code=fs.readFileSync('static/console.html','utf8').split('<script>')[1].split('</script>')[0];
vm.runInNewContext(code+'\nrenderEvents(data,null);',{document,window,location,Node:E,encodeURIComponent,decodeURIComponent,Number,String,Array,data});
const text=els['#view'].textContent;for(const v of ['auth-demo','auth-normalized','failure','2026-01-01T00:01:00'])assert(text.includes(v),v);
'''
    run = subprocess.run(['node', '-e', harness], input=json.dumps(data), text=True, capture_output=True)
    assert run.returncode == 0, run.stderr


def test_synthetic_sender_uses_single_local_batch(monkeypatch):
    import sys
    from pathlib import Path
    monkeypatch.syspath_prepend(str(Path('scripts').resolve()))
    import collect_auth_synthetic as sender
    calls = []
    monkeypatch.setenv('AEGIS_COLLECTOR_TOKEN', 'dummy-token')
    monkeypatch.setattr(sys, 'argv', ['collect_auth_synthetic.py', '--collector-id', 'demo'])
    monkeypatch.setattr(sender, 'post', lambda *a: calls.append(a) or {'analysis_id': 'a'})
    assert sender.main() == 0
    assert len(calls) == 1 and calls[0][1] == '/api/v1/ingest/auth'
    assert [event['outcome'] for event in calls[0][2]['events']] == ['failure'] * 3 + ['success']


def test_synthetic_sender_disables_environment_proxy(monkeypatch):
    from pathlib import Path
    import urllib.request
    monkeypatch.syspath_prepend(str(Path('scripts').resolve()))
    import collect_synthetic as sender
    captured = []
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self): return b'{"analysis_id":"a"}'
    class Opener:
        def open(self, request, timeout): return Response()
    def build(*handlers):
        captured.extend(handlers)
        return Opener()
    monkeypatch.setenv('HTTP_PROXY', 'http://proxy.invalid:3128')
    monkeypatch.setattr(urllib.request, 'build_opener', build)
    assert sender.post(8000, '/api/v1/ingest/auth', {}, 'dummy')['analysis_id'] == 'a'
    assert any(isinstance(h, urllib.request.ProxyHandler) and h.proxies == {} for h in captured)
    assert any(isinstance(h, sender._NoRedirect) for h in captured)
