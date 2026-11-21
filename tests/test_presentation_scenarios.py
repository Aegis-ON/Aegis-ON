"""Synthetic local presentation cases through the real collection API."""
import importlib
import json
import sys
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from aegis_on import api
from aegis_on.attack_model import AttackModel
from aegis_on.codebert_shadow import ShadowModel
from aegis_on.collector_auth import CollectorRegistry
from aegis_on.history_store import SQLiteHistory
from aegis_on.pii import PIIDetector
from aegis_on.service import DetectionService


def test_scenarios_use_real_collector_api_and_do_not_join_unrelated_logs(tmp_path, monkeypatch, capsys):
    monkeypatch.syspath_prepend(str(Path('scripts').resolve()))
    sender = importlib.import_module('presentation_scenarios')
    database = tmp_path / 'history.sqlite3'
    store = SQLiteHistory(database)
    monkeypatch.setenv('AEGIS_API_TOKEN', 'fictional-analyst-token')
    monkeypatch.setenv('AEGIS_ANALYST_NAME', 'fictional-analyst')
    monkeypatch.setenv('AEGIS_ALLOW_LEGACY_COLLECTOR_TOKEN', '0')
    monkeypatch.setattr(api, 'service', DetectionService(store))
    monkeypatch.setattr(api, 'attack_model', AttackModel())
    monkeypatch.setattr(api, 'codebert_shadow', ShadowModel())
    monkeypatch.setattr(api, 'pii_detector', PIIDetector())
    secret = CollectorRegistry(store).register('demo-collector')
    sent = []
    with TestClient(api.app, base_url='https://testserver') as client:
        def post(port, path, body, token, headers):
            assert port == 8000 and token == secret
            sent.append((path, body))
            response = client.post(path, json=body, headers={**headers, 'Authorization': 'Bearer ' + token})
            assert response.status_code == 200, response.text
            return response.json()
        monkeypatch.setattr(sender, 'post', post)
        for name in ('normal', 'auth', 'fanout'):
            sender.send_scenario(name, 8000, 'demo-collector', secret)
        history = client.get('/api/v1/history', headers={'Authorization': 'Bearer fictional-analyst-token'}).json()
        assert len(history['analyses']) == 6
        normal = next(b for b in history['analyses'] if b['input_type'] == 'sysmon' and b['source_events'][0]['sysmon_event_id'] == 1)
        assert normal['detection_ids'] == []
        detections = history['detections']
        auth = next(d for d in detections if d['technique'] == 'authentication-review')
        fanout = next(d for d in detections if d['technique'] == 'T1595' and d['source'] == 'correlation')
        assert len(auth['event_ids']) == 4 and len(fanout['event_ids']) == 3
        assert set(auth['event_ids']).isdisjoint(fanout['event_ids'])
        assert any('not proof' in evidence for evidence in fanout['evidence'])
        assert len([x for x in sent if x[0].endswith('/auth')]) == 2
        assert len([x for x in sent if x[0].endswith('/sysmon')]) == 4
        # A new run must not silently resend fixed source IDs.
        sender.send_scenario('fanout', 8000, 'demo-collector', secret)
        latest = client.get('/api/v1/history', headers={'Authorization': 'Bearer fictional-analyst-token'}).json()
        assert len([d for d in latest['detections'] if d['technique'] == 'T1595']) == 2
        raw_ids = [item['System']['EventRecordID'] for path, body in sent if path.endswith('/sysmon') for item in body['events']]
        assert len(raw_ids) == len(set(raw_ids))
        assert secret not in json.dumps(latest)
        assert secret not in capsys.readouterr().out
    assert secret.encode() not in database.read_bytes()


def test_generated_inputs_are_fictional_and_respect_batch_boundaries(monkeypatch):
    monkeypatch.syspath_prepend(str(Path('scripts').resolve()))
    sender = importlib.import_module('presentation_scenarios')
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for scenario, expected in [('normal', [1]), ('auth', [3, 1]), ('fanout', [1, 1, 1])]:
        rows = sender.build_batches(scenario, 'abcdef0123456789abcdef0123456789', start)
        assert [len(body['events']) for _, body in rows] == expected
        assert not any(word in json.dumps(rows).lower() for word in ('password', 'cookie', 'authorization'))


def test_failure_output_does_not_include_credential_or_server_body(monkeypatch, capsys):
    monkeypatch.syspath_prepend(str(Path('scripts').resolve()))
    sender = importlib.import_module('presentation_scenarios')
    secret = 'fictional-secret-value'
    monkeypatch.setenv('AEGIS_COLLECTOR_TOKEN', secret)
    monkeypatch.setattr(sys, 'argv', ['presentation_scenarios.py', 'auth'])
    def fail(*args, **kwargs):
        raise urllib.error.HTTPError('http://127.0.0.1', 401, secret, {}, None)
    monkeypatch.setattr(sender, 'post', fail)
    assert sender.main() == 1
    output = capsys.readouterr()
    assert secret not in output.out + output.err
    assert 'HTTP 401' in output.err
