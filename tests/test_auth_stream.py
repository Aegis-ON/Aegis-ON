"""Authentication stream semantics use fictional events and isolated SQLite files."""
import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from aegis_on import api
from aegis_on.history_store import SQLiteHistory
from aegis_on.service import DetectionService


@pytest.fixture
def stream(tmp_path, monkeypatch):
    path = tmp_path / 'history.db'
    monkeypatch.setenv('AEGIS_API_TOKEN', 'synthetic-token')
    monkeypatch.setenv('AEGIS_ANALYST_NAME', 'analyst')
    monkeypatch.setenv('AEGIS_ALLOW_LEGACY_COLLECTOR_TOKEN', '1')
    monkeypatch.setattr(api, 'service', DetectionService(SQLiteHistory(path)))
    with TestClient(api.app, base_url='https://testserver') as client:
        def send(events, batch, collector='one'):
            headers = {'Authorization':'Bearer synthetic-token','X-Collector-ID':collector,'Idempotency-Key':batch}
            return client.post('/api/v1/ingest/auth', json={'events':events}, headers=headers)
        def history():
            return client.get('/api/v1/history', headers={'Authorization':'Bearer synthetic-token'}).json()
        yield send, history, path, client


def event(i, outcome=None, **kwargs):
    return {'event_id':f'e{i}', 'timestamp':f'2026-01-01T00:0{i}:00Z', 'host':'fictional-host',
            'account':'realm\\fixture-user', 'source_ip':'192.0.2.1',
            'outcome':outcome or ('success' if i == 3 else 'failure'), **kwargs}


def test_out_of_order_batches_restart_mixed_and_approval(stream):
    send, history, path, client = stream
    # Success arrives before failures; a later batch supplies missing evidence.
    assert send([event(3)], 'a').status_code == 200
    assert send([event(2)], 'b').status_code == 200
    api.service = DetectionService(SQLiteHistory(path))
    assert send([event(0),event(2),event(1)], 'c').json()['summary']['duplicate'] == 1
    h = history(); assert len(h['detections']) == 1
    alert = h['detections'][0]
    assert len(alert['event_ids']) == 4 and alert['source'] == 'correlation'
    assert len({e['event_id'] for b in h['analyses'] for e in b['source_events']}) == 4
    assert all(b.get('received_at') for b in h['analyses'])
    # A complete replay under another batch key must not duplicate the alert.
    assert send([event(i) for i in range(4)], 'retry').json()['summary']['duplicate'] == 4
    assert len(history()['detections']) == 1
    approval = client.post('/api/v1/detections/'+alert['detection_id']+'/approval',
                           json={'analyst':'analyst', 'rationale':'review'},
                           headers={'Authorization':'Bearer synthetic-token'})
    assert approval.status_code == 200 and approval.json()['simulation_only'] is True
    # A later-arriving earlier failure adds evidence: old simulated approval is unchanged.
    late = event(4, 'failure', timestamp='2025-12-31T23:59:30Z')
    assert send([late], 'late').status_code == 200
    after = history()['detections']; assert len(after) == 2
    assert len(next(d for d in after if d.get('approval'))['event_ids']) == 4
    assert len(next(d for d in after if not d.get('approval'))['event_ids']) == 5
    assert b'fixture-user' not in path.read_bytes() and b'192.0.2.1' not in path.read_bytes()


def test_same_time_other_identity_and_invalid_placeholders(stream):
    send, history, _, _ = stream
    same = [event(i, timestamp='2026-01-01T00:01:00Z') for i in range(4)]
    assert send(same, 'same').status_code == 200
    assert history()['detections'] == []
    for i, change in enumerate(({'account':'other'}, {'host':'other'}, {'source_ip':'192.0.2.2'})):
        records = [event(j, event_id=f'group{i}-{j}', **(change if j == 3 else {})) for j in range(4)]
        assert send(records, f'separate-{i}', collector=f'source-{i}').status_code == 200
    assert history()['detections'] == []
    for i, change in enumerate(({'account':' '}, {'account':'unknown'}, {'host':'-'}, {'source_ip':'0.0.0.0'}, {'source_ip':'::'})):
        assert send([event(0, **change)], f'invalid-{i}').status_code == 422


def test_conflict_rolls_back_batch_and_missing_key_fails_closed(stream):
    send, history, path, _ = stream
    assert send([event(0)], 'a').status_code == 200
    bad = send([event(1), event(0, outcome='success')], 'conflict')
    assert bad.status_code == 409
    assert sum(len(b['source_events']) for b in history()['analyses']) == 1
    key = Path(str(path) + '.correlation-key')
    key.unlink()
    assert send([event(1)], 'key-lost').status_code == 503
    assert sum(len(b['source_events']) for b in history()['analyses']) == 1
    assert not key.exists()


def test_concurrent_replays_have_no_duplicate_observations(stream):
    send, history, _, _ = stream
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda i: send([event(0)], f'parallel-{i}'), range(4)))
    assert all(r.status_code == 200 for r in results)
    assert sum(r.json()['summary']['processed'] for r in results) == 1
    assert sum(len(b['source_events']) for b in history()['analyses']) == 1


def test_repeated_successes_are_distinct_review_events(stream):
    send, history, _, _ = stream
    assert send([event(i) for i in range(4)], 'first').status_code == 200
    assert send([event(4, 'success')], 'second').status_code == 200
    alerts = history()['detections']
    assert len(alerts) == 2
    assert set(alerts[0]['event_ids'][:-1]) == set(alerts[1]['event_ids'][:-1])
    assert alerts[0]['event_ids'][-1] != alerts[1]['event_ids'][-1]


def test_hmac_fingerprints_group_and_key_replacement(stream):
    send, history, path, _ = stream
    records = [event(i) for i in range(4)]
    assert send(records, 'first').status_code == 200
    with sqlite3.connect(path) as db:
        assert all(x[0].startswith('hmac-v2:') for x in db.execute('SELECT fingerprint FROM stream_events'))
        assert db.execute('SELECT digest FROM collected_batches').fetchone()[0].startswith('hmac-v2:')
        groups = {x[0] for x in db.execute('SELECT group_key FROM auth_correlation_events')}
        assert len(groups) == 1
    sources = history()['analyses'][0]['source_events']
    assert len({s['auth_correlation_group'] for s in sources}) == 1
    key = Path(str(path) + '.correlation-key')
    key.write_bytes(b'X' * 32)
    assert send([event(4)], 'changed-key').status_code == 503
    assert len(history()['analyses']) == 1


def test_key_write_failure_is_recoverable(stream):
    send, history, path, _ = stream
    with patch('aegis_on.history_store.os.fsync', side_effect=OSError('synthetic failure')):
        assert send([event(0)], 'first').status_code == 503
    assert not Path(str(path) + '.correlation-key').exists()
    assert not list(path.parent.glob('.aegis-correlation-*'))
    assert send([event(0)], 'first').status_code == 200
    assert len(history()['analyses']) == 1


def test_damaged_v3_migration_rolls_back(tmp_path):
    path = tmp_path / 'bad.sqlite3'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE stream_events (event_key TEXT, fingerprint TEXT, collector_id TEXT, host_key TEXT, occurred TEXT, destination_key TEXT, outbound INTEGER, event_id TEXT, host_display TEXT)')
        db.execute('CREATE TABLE stream_alerts (collector_id TEXT, host_key TEXT, detection_id TEXT, event_ids TEXT)')
        db.execute('PRAGMA user_version=3')
    os.chmod(path, 0o600)
    from aegis_on.history_store import HistoryError
    with pytest.raises(HistoryError):
        SQLiteHistory(path).list_snapshot()
    with sqlite3.connect(path) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 3
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE name LIKE 'auth_correlation_%'").fetchone()[0] == 0


def test_sparse_old_and_new_changes_do_not_scan_in_between(tmp_path):
    from datetime import datetime, timedelta, timezone
    store = SQLiteHistory(tmp_path / 'sparse.db')
    store.list_collectors()
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    with sqlite3.connect(store.path) as db:
        db.execute('BEGIN')
        for i in range(5010):
            key = f'e{i}'
            timestamp = (start + timedelta(hours=i)).isoformat()
            db.execute('INSERT INTO stream_events VALUES (?,?,?,?,?,?,?,?,?)',
                       (key, 'fingerprint', 'c', 'host', timestamp, None, 0, key, '[HOST]'))
            db.execute('INSERT INTO auth_correlation_events VALUES (?,?,?,?,?,?)',
                       (key, 'group', timestamp, 'failure', key, '[HOST]'))
        batch = {'detection_ids': []}
        changed = [{'group_key':'group', 'occurred':start.isoformat()},
                   {'group_key':'group', 'occurred':(start + timedelta(hours=5009)).isoformat()}]
        SQLiteHistory._auth_correlate(db, 1, batch, changed)
        assert batch['detection_ids'] == []


def test_separate_python_process_continues_auth_correlation(stream):
    import subprocess
    import sys
    send, history, path, _ = stream
    assert send([event(i) for i in range(3)], 'first').status_code == 200
    code = r'''
import json,sys
from fastapi.testclient import TestClient
from aegis_on import api
from aegis_on.service import DetectionService
from aegis_on.history_store import SQLiteHistory
api.service=DetectionService(SQLiteHistory(sys.argv[1]))
with TestClient(api.app,base_url='https://testserver') as c:
 h={'Authorization':'Bearer synthetic-token','X-Collector-ID':'one','Idempotency-Key':'next-process'}
 r=c.post('/api/v1/ingest/auth',json={'events':[json.loads(sys.stdin.read())]},headers=h)
 assert r.status_code==200, r.text
 print(json.dumps(c.get('/api/v1/history',headers=h).json()))
'''
    run = subprocess.run([sys.executable, '-c', code, str(path)], input=json.dumps(event(3)), text=True,
                         capture_output=True, env={**os.environ, 'PYTHONPATH': 'src'}, check=True)
    result = json.loads(run.stdout)
    assert len(result['detections']) == 1 and len(result['detections'][0]['event_ids']) == 4
    assert len(history()['detections']) == 1


def test_same_batch_v3_replay_indexes_old_records(stream):
    import hashlib
    from aegis_on.auth_log import normalize_auth
    send, history, path, client = stream
    records = [event(i) for i in range(3)]
    assert send(records, 'first').status_code == 200
    headers = {'Authorization':'Bearer synthetic-token','X-Collector-ID':'one','Idempotency-Key':'first'}
    request = client.build_request('POST', '/api/v1/ingest/auth', json={'events':records}, headers=headers)
    digest = hashlib.sha256(request.content).hexdigest()
    _, entries = normalize_auth({'events':records}, 'one')
    with sqlite3.connect(path) as db:
        for item in entries:
            db.execute('UPDATE stream_events SET fingerprint=? WHERE event_key=?', (item['fingerprint'], item['event_key']))
        db.execute('UPDATE collected_batches SET digest=? WHERE batch_id=?', (digest, 'first'))
        db.execute('DROP TABLE stream_alert_spans')
        db.execute('DROP INDEX stream_host_event_id')
        db.execute('DROP TABLE auth_correlation_alerts')
        db.execute('DROP TABLE auth_correlation_events')
        db.execute('DROP TABLE auth_correlation_meta')
        db.execute('PRAGMA user_version=3')
    Path(str(path) + '.correlation-key').unlink()
    api.service = DetectionService(SQLiteHistory(path))
    replay = send(records, 'first')
    assert replay.status_code == 200 and replay.json()['replayed']
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT count(*) FROM auth_correlation_events').fetchone()[0] == 3
        assert all(row[0].startswith('hmac-v2:') for row in db.execute('SELECT fingerprint FROM stream_events'))
    assert send([event(3)], 'success').status_code == 200
    assert len(history()['detections']) == 1


def test_many_separated_changed_windows_do_not_merge_unboundedly(tmp_path):
    from datetime import datetime, timedelta, timezone
    store = SQLiteHistory(tmp_path / 'dense.db'); store.list_collectors()
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    with sqlite3.connect(store.path) as db:
        for i in range(5001):
            key, ts = f'e{i}', (start + timedelta(minutes=i)).isoformat()
            db.execute('INSERT INTO stream_events VALUES (?,?,?,?,?,?,?,?,?)', (key, 'f', 'c', 'h', ts, None, 0, key, 'host'))
            db.execute('INSERT INTO auth_correlation_events VALUES (?,?,?,?,?,?)', (key, 'group', ts, 'failure', key, 'host'))
        changed = [{'group_key':'group', 'occurred':(start + timedelta(minutes=20*i)).isoformat()} for i in range(251)]
        result = {'detection_ids': []}
        SQLiteHistory._auth_correlate(db, 1, result, changed)
        assert result['detection_ids'] == []


def test_correlation_evidence_dom_shows_sources_times_and_group(stream):
    import shutil
    import subprocess
    if not shutil.which('node'):
        pytest.skip('Node not installed')
    send, history, _, _ = stream
    for i in range(4):
        assert send([event(i)], f'b{i}').status_code == 200
    data = history()
    groups = {e['auth_correlation_group'] for b in data['analyses'] for e in b['source_events']}
    assert len(groups) == 1
    harness = r'''
const assert=require('assert'),vm=require('vm'),fs=require('fs');
class E{constructor(tag='div'){this.tag=tag;this.children=[];this._text='';this.value='';this.style={};this.classList={add(){}};}set textContent(x){this._text=String(x)}get textContent(){return this._text+this.children.map(x=>x.textContent).join('')}get childNodes(){return this.children}append(...xs){this.children.push(...xs)}addEventListener(){}setAttribute(){}replaceChildren(...xs){this.children=xs;this._text=''}}
const els=Object.fromEntries(['#kicker','#title','#subtitle','#status','#view','#load'].map(x=>[x,new E()]));
const document={querySelector:q=>els[q]||null,createElement:t=>new E(t)},window={},location={pathname:'/console/detections'};
const data=JSON.parse(fs.readFileSync(0,'utf8'));
const code=fs.readFileSync('static/console.html','utf8').split('<script>')[1].split('</script>')[0];
let ctx={document,window,location,Node:E,encodeURIComponent,decodeURIComponent,Number,String,Array,data};
vm.runInNewContext(code+'\nglobalThis.box=evidencePanel(data.detections[0],linkedEvents(data,data.detections[0]),null);',ctx);
const text=ctx.box.textContent;assert.equal((text.match(/AUTH-GROUP/g)||[]).length,4);
for(const v of ['수집기 one','발생 시각','서버 수신','auth-normalized','observed period','시뮬레이션'])assert(text.includes(v),v);
'''
    run = subprocess.run(['node', '-e', harness], input=json.dumps(data), text=True, capture_output=True)
    assert run.returncode == 0, run.stderr
