"""Behavioral checks of persistent outbound windows using fictional data only."""
from datetime import datetime, timedelta
import json
import shutil
import subprocess
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from aegis_on import api
from aegis_on.attack_model import AttackModel
from aegis_on.codebert_shadow import ShadowModel
from aegis_on.history_store import SQLiteHistory
from aegis_on.pii import PIIDetector
from aegis_on.service import DetectionService
from test_sysmon_api import make_event


@pytest.fixture
def soc(tmp_path):
    db = tmp_path / 'history.sqlite3'
    with (patch.dict('os.environ', {'AEGIS_API_TOKEN': 'synthetic-token',
                                  'AEGIS_ANALYST_NAME': 'analyst-1',
                                  'AEGIS_ALLOW_LEGACY_COLLECTOR_TOKEN': '1'}),
          patch.object(api, 'service', DetectionService(SQLiteHistory(db))),
          patch.object(api, 'pii_detector', PIIDetector()),
          patch.object(api, 'attack_model', AttackModel()),
          patch.object(api, 'codebert_shadow', ShadowModel()),
          TestClient(api.app, base_url='https://testserver') as client):
        yield client, db


def event(record, minute, address, *, host='FIXTURE-HOST', initiated='true', process=None):
    e = make_event(3, record)
    e['System']['Computer'] = host
    e['EventData']['UtcTime'] = (datetime(2026, 1, 1) + timedelta(minutes=minute)).strftime('%Y-%m-%d %H:%M:%S.000')
    e['EventData']['DestinationIp'] = address
    if initiated is None:
        e['EventData'].pop('Initiated', None)
    else:
        e['EventData']['Initiated'] = initiated
    if process:
        e['EventData']['ProcessGuid'] = process
    return e


def send(client, key, events, collector='collector-a'):
    return client.post('/api/v1/ingest/sysmon', json={'events': events}, headers={
        'Authorization': 'Bearer synthetic-token', 'X-Collector-ID': collector,
        'Idempotency-Key': key,
    })


def snapshot(client):
    return client.get('/api/v1/history', headers={'Authorization': 'Bearer synthetic-token'}).json()


def windows(data):
    lookup = {str(e['event_id']): e.get('record_id') for b in data['analyses'] for e in b['source_events']}
    return [(frozenset(lookup[i] for i in d['event_ids']), d)
            for d in data['detections'] if d['source'] == 'correlation']


def sample():
    return [event(i + 1, minute, f'198.51.100.{i + 1}') for i, minute in enumerate((0, 5, 9, 11, 12))]


@pytest.mark.parametrize('separate', [False, True])
def test_overlapping_windows_preserve_both_sets(soc, separate):
    client, _ = soc
    rows = sample()
    chunks = [rows[:3], rows[3:]] if separate else [rows]
    for i, chunk in enumerate(chunks):
        response = send(client, f'batch-{i}', chunk)
        assert response.status_code == 200, response.text
    observed = {ids for ids, _ in windows(snapshot(client))}
    assert frozenset({1, 2, 3}) in observed
    assert frozenset({2, 3, 4, 5}) in observed


def test_retransmission_mixed_conflict_and_atomic_history(soc):
    client, _ = soc
    a, b, c, d, e = sample()
    assert send(client, 'initial', [a, b, c]).status_code == 200
    initial = snapshot(client)
    replay = send(client, 'replay-new-key', [a, b, c])
    assert replay.status_code == 200 and replay.json()['summary']['duplicate'] == 3
    assert len(windows(snapshot(client))) == len(windows(initial))
    mixed = send(client, 'mixed', [a, d, e])
    assert mixed.status_code == 200 and mixed.json()['summary']['duplicate'] == 1
    after = snapshot(client)
    assert {ids for ids, _ in windows(after)} >= {frozenset({1, 2, 3}), frozenset({2, 3, 4, 5})}
    assert sum(len(b['source_events']) for b in after['analyses']) == 5
    conflict = event(1, 0, '198.51.100.200')
    never_saved = event(99, 13, '198.51.100.99')
    failure = send(client, 'conflict', [conflict, never_saved])
    assert failure.status_code == 409
    assert snapshot(client) == after


def test_inclusive_ten_minute_boundary_and_same_timestamp(soc):
    client, _ = soc
    rows = [event(10, 0, '198.51.100.10'), event(11, 0, '198.51.100.11'),
            event(12, 10, '198.51.100.12'), event(13, 11, '198.51.100.13')]
    assert send(client, 'equal-time', list(reversed(rows))).status_code == 200
    data = snapshot(client)
    sets = {ids for ids, _ in windows(data)}
    assert frozenset({10, 11, 12}) in sets
    assert frozenset({10, 11, 12, 13}) not in sets
    assert not any(({10} <= s) != ({11} <= s) for s in sets)


def test_late_arrival_and_restart_correlate_by_event_time(soc):
    client, db = soc
    rows = sample()
    assert send(client, 'late-first', [rows[2], rows[3], rows[4]]).status_code == 200
    # Replace the history object: this reopens the existing SQLite DB.
    api.service = DetectionService(SQLiteHistory(db))
    assert send(client, 'late-second', [rows[1], rows[0]]).status_code == 200
    observed = {ids for ids, _ in windows(snapshot(client))}
    assert frozenset({1, 2, 3}) in observed
    assert frozenset({2, 3, 4, 5}) in observed


def test_approved_evidence_is_immutable_and_new_window_pending(soc):
    client, _ = soc
    rows = sample()
    assert send(client, 'before-approval', rows[:3]).status_code == 200
    first = windows(snapshot(client))[0][1]
    response = client.post(f"/api/v1/detections/{first['detection_id']}/approval",
                           headers={'Authorization': 'Bearer synthetic-token'},
                           json={'analyst': 'analyst-1', 'rationale': 'synthetic review'})
    assert response.status_code == 200
    evidence_at_approval = windows(snapshot(client))[0][1]['evidence']
    assert send(client, 'after-approval', rows[3:]).status_code == 200
    found = windows(snapshot(client))
    approved = next(d for ids, d in found if ids == frozenset({1, 2, 3}))
    followup = next(d for ids, d in found if ids == frozenset({2, 3, 4, 5}))
    assert approved['detection_id'] == first['detection_id']
    assert approved['evidence'] == evidence_at_approval
    assert approved['approval']['rationale'] == 'synthetic review'
    assert followup['status'] == 'pending_review' and 'approval' not in followup


def test_pending_window_extends_and_disjoint_window_is_separate(soc):
    client, _ = soc
    first = [event(i + 30, i, f'198.51.100.{i + 30}') for i in range(3)]
    assert send(client, 'pending', first).status_code == 200
    previous = windows(snapshot(client))[0][1]
    extra = event(33, 3, '198.51.100.33')
    assert send(client, 'extend', [extra]).status_code == 200
    extended = windows(snapshot(client))
    assert len(extended) == 1
    assert extended[0][0] == frozenset({30, 31, 32, 33})
    assert extended[0][1]['detection_id'] == previous['detection_id']
    assert extended[0][1]['status'] == 'pending_review'
    later = [event(i + 40, 30 + i, f'198.51.100.{i + 40}') for i in range(3)]
    assert send(client, 'disjoint', later).status_code == 200
    assert {ids for ids, _ in windows(snapshot(client))} == {
        frozenset({30, 31, 32, 33}), frozenset({40, 41, 42})}


def test_approved_window_does_not_change_when_superset_arrives(soc):
    client, _ = soc
    rows = [event(200 + i, i, f'198.51.100.{i + 1}') for i in range(4)]
    assert send(client, 'before', rows[:3]).status_code == 200
    original = windows(snapshot(client))[0][1]
    approved = client.post(f"/api/v1/detections/{original['detection_id']}/approval",
                           headers={'Authorization': 'Bearer synthetic-token'},
                           json={'analyst': 'analyst-1', 'rationale': 'synthetic review'})
    assert approved.status_code == 200
    before = next(d for _, d in windows(snapshot(client)) if d['detection_id'] == original['detection_id'])
    assert send(client, 'later', rows[3:]).status_code == 200
    after = windows(snapshot(client))
    assert next(d for _, d in after if d['detection_id'] == original['detection_id']) == before
    assert any(ids == frozenset({200, 201, 202, 203}) and d['status'] == 'pending_review'
               for ids, d in after)


def test_authorized_monitoring_still_needs_review_without_attack_claim(soc):
    client, _ = soc
    # The operator's authorization is scenario context, not information the
    # current collector can independently verify.
    monitoring = [event(300 + i, i, f'192.0.2.{10 + i}') for i in range(3)]
    assert send(client, 'monitoring', monitoring).status_code == 200
    alerts = windows(snapshot(client))
    assert len(alerts) == 1
    assert alerts[0][1]['status'] == 'pending_review'
    assert 'not proof of scanning or attack' in ' '.join(alerts[0][1]['evidence'])


def test_dense_one_thousand_events_are_processed_without_spurious_limit(soc):
    client, _ = soc
    rows = []
    for i in range(1000):
        e = event(10000 + i, 0, f'198.51.100.{i % 3 + 1}')
        e['EventData']['UtcTime'] = (datetime(2026, 1, 1) + timedelta(milliseconds=100 * i)).strftime('%Y-%m-%d %H:%M:%S.%f')
        rows.append(e)
    response = send(client, 'dense', rows)
    assert response.status_code == 200, response.text
    data = snapshot(client)
    assert sum(len(b['source_events']) for b in data['analyses']) == 1000
    found = windows(data)
    assert len(found) == 1
    assert len(found[0][0]) == 1000
    assert '3 unique destinations' in ' '.join(found[0][1]['evidence'])


def test_resource_limit_rejects_complete_batch_without_partial_ack(soc):
    client, _ = soc
    original = [event(8000, 0, '198.51.100.1'), event(8001, 1, '198.51.100.2')]
    assert send(client, 'prior', original).status_code == 200
    before = snapshot(client)
    many = [event(11000 + i, 100 + i, f'198.51.100.{i % 3 + 1}') for i in range(1000)]
    failure = send(client, 'resource-limit', many)
    assert failure.status_code == 503, failure.text
    assert snapshot(client) == before
    # A rejected transaction must not reserve the idempotency key or any event.
    retry = send(client, 'resource-limit', many[:3])
    assert retry.status_code == 200, retry.text
    assert retry.json()['summary']['processed'] == 3


def test_hosts_collectors_directions_ipv4_mapping_and_process_scope(soc):
    client, _ = soc
    rows = [event(20, 0, '192.0.2.1'), event(21, 1, '::ffff:192.0.2.1'),
            event(22, 2, '192.0.2.2'), event(23, 3, '192.0.2.3', initiated='false'),
            event(24, 4, '192.0.2.4', initiated=None),
            event(25, 5, '192.0.2.5', host='OTHER-HOST')]
    assert send(client, 'scopes', rows).status_code == 200
    assert not windows(snapshot(client)), 'mapped IPv4, inbound, unknown and other host must not inflate count'
    third = event(26, 6, '192.0.2.6', process='{00000000-0000-0000-0000-000000000002}')
    assert send(client, 'other-collector', [third], collector='collector-b').status_code == 200
    assert not windows(snapshot(client)), 'different collectors must not be merged'
    assert send(client, 'same-host', [third]).status_code == 200
    matches = windows(snapshot(client))
    assert len(matches) == 1
    ids, alert = matches[0]
    assert ids == frozenset({20, 21, 22, 26})
    assert 'process' in ' '.join(alert['evidence']).lower()
    assert '198.51.' not in str(snapshot(client))


@pytest.mark.skipif(not shutil.which('node'), reason='Node.js required for console DOM check')
def test_actual_api_evidence_and_all_related_events_reach_console_dom(soc):
    client, _ = soc
    rows = sample()
    assert send(client, 'ui-initial', rows[:3]).status_code == 200
    assert send(client, 'ui-later', rows[3:]).status_code == 200
    data = snapshot(client)
    followup = next(d for ids, d in windows(data) if ids == frozenset({2, 3, 4, 5}))
    harness = r'''
const assert=require('assert'),vm=require('vm'),fs=require('fs');
class E {constructor(t='div'){this.tag=t;this.children=[];this._text='';this.classList={add(){}};this.style={}}
set textContent(x){this._text=String(x);this.children=[]}get textContent(){return this._text+this.children.map(x=>x.textContent).join('')}
get childNodes(){return this.children}append(...xs){this.children.push(...xs)}addEventListener(){}setAttribute(){}}
const elements=Object.fromEntries(['#kicker','#title','#subtitle','#status','#view','#load'].map(k=>[k,new E()]));
const document={querySelector:q=>elements[q]||null,createElement:t=>new E(t)};
const data=JSON.parse(fs.readFileSync(0,'utf8')), det=data.detections.find(d=>d.detection_id===process.argv[1]);
const code=fs.readFileSync('static/console.html','utf8').split('<script>')[1].split('</script>')[0];
vm.runInNewContext(code+'\nview.append(evidencePanel(det, linkedEvents(data,det), ""));',{document,window:{},location:{pathname:'/console/detections'},Node:E,data,det,encodeURIComponent,decodeURIComponent,Number,String,Array});
const text=elements['#view'].textContent;
for(const id of det.event_ids)assert(text.includes(id),id);
for(const s of ['출처 상관분석','4 unique destinations','서버 수신','시뮬레이션'])assert(text.includes(s),s);
'''
    result = subprocess.run(['node', '-e', harness, followup['detection_id']],
                            input=json.dumps(data), text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
