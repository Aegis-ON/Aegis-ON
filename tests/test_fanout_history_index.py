"""Migration and long-lived fanout history: synthetic SQLite data only."""
import concurrent.futures
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import sqlite3
import time
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from aegis_on import api
from aegis_on.attack_model import AttackModel
from aegis_on.codebert_shadow import ShadowModel
from aegis_on.history_store import HistoryError, SQLiteHistory
from aegis_on.pii import PIIDetector
from aegis_on.service import DetectionService
from test_stream_fanout_windows import event, send


def host_key(collector='collector-a', host='FIXTURE-HOST'):
    return hashlib.sha256(json.dumps([collector, host.casefold()], ensure_ascii=True,
                                      sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def make_v4(path, count=1, ids_per_alert=3, *, missing=False, approved=False):
    """Construct structurally valid v4 history without invoking a new loader.

    The repeated alert sets deliberately stress accumulated ID-list size while
    keeping the source-event table compact. Each reference resolves to the same
    collector and host, and each alert spans less than ten minutes.
    """
    schema = '''
    CREATE TABLE analyses (sequence INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL);
    CREATE TABLE detections (sequence INTEGER PRIMARY KEY AUTOINCREMENT, analysis_sequence INTEGER NOT NULL REFERENCES analyses(sequence), detection_id TEXT NOT NULL UNIQUE, payload TEXT NOT NULL, approval TEXT);
    CREATE TABLE collectors (collector_id TEXT PRIMARY KEY, last_received_at TEXT, last_heartbeat_at TEXT, reported_state TEXT, last_error_at TEXT, last_error_code TEXT);
    CREATE TABLE collected_batches (collector_id TEXT NOT NULL, batch_id TEXT NOT NULL, input_type TEXT NOT NULL, digest TEXT NOT NULL, analysis_sequence INTEGER NOT NULL REFERENCES analyses(sequence), PRIMARY KEY(collector_id,batch_id));
    CREATE TABLE stream_events (event_key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, collector_id TEXT NOT NULL, host_key TEXT NOT NULL, occurred TEXT NOT NULL, destination_key TEXT, outbound INTEGER NOT NULL, event_id TEXT NOT NULL, host_display TEXT NOT NULL);
    CREATE INDEX stream_host_time ON stream_events(collector_id,host_key,occurred);
    CREATE TABLE stream_alerts (collector_id TEXT NOT NULL, host_key TEXT NOT NULL, detection_id TEXT NOT NULL UNIQUE REFERENCES detections(detection_id), event_ids TEXT NOT NULL);
    CREATE TABLE auth_correlation_meta (key_id TEXT NOT NULL);
    CREATE TABLE auth_correlation_events (event_key TEXT PRIMARY KEY REFERENCES stream_events(event_key), group_key TEXT NOT NULL, occurred TEXT NOT NULL, outcome TEXT NOT NULL, event_id TEXT NOT NULL, host_display TEXT NOT NULL);
    CREATE INDEX auth_group_time ON auth_correlation_events(group_key,occurred);
    CREATE TABLE auth_correlation_alerts (success_key TEXT NOT NULL, detection_id TEXT NOT NULL UNIQUE REFERENCES detections(detection_id));
    PRAGMA user_version=4;
    '''
    ids = [f'00000000-0000-4000-8000-{i:012d}' for i in range(ids_per_alert)]
    ids_json = json.dumps(ids, separators=(',', ':'))
    key = host_key()
    with sqlite3.connect(path) as db:
        db.executescript(schema)
        db.execute('INSERT INTO analyses(payload) VALUES (?)', (json.dumps({'analysis_id': 'old-batch'}),))
        records = [(f'old-key-{i}', 'full-v1:' + 'a' * 64, 'collector-a', key,
                    f'2025-01-01T00:00:{i:02d}+00:00', f'destination-{i}', 1, ident, '[HOST:old]')
                   for i, ident in enumerate(ids) if not (missing and i == len(ids) - 1)]
        db.executemany('INSERT INTO stream_events VALUES (?,?,?,?,?,?,?,?,?)', records)
        def detection_rows():
            for n in range(count):
                ident = f'old-alert-{n}'
                payload = {'detection_id': ident, 'source': 'correlation', 'technique': 'T1595',
                           'event_ids': ids, 'host': '[HOST:old]', 'evidence': ['old evidence'],
                           'status': 'approved_for_simulated_response' if approved and n == 0 else 'pending_review'}
                approval = json.dumps({'simulation_only': True, 'analyst': 'analyst-1',
                                       'rationale': 'old synthetic approval'}) if approved and n == 0 else None
                yield (1, ident, json.dumps(payload, separators=(',', ':')), approval)
        db.executemany('INSERT INTO detections(analysis_sequence,detection_id,payload,approval) VALUES (?,?,?,?)', detection_rows())
        db.executemany('INSERT INTO stream_alerts VALUES (?,?,?,?)',
                       (('collector-a', key, f'old-alert-{i}', ids_json) for i in range(count)))
    os.chmod(path, 0o600)
    return ids


@contextmanager
def client_at(path, monkeypatch):
    monkeypatch.setenv('AEGIS_API_TOKEN', 'synthetic-token')
    monkeypatch.setenv('AEGIS_ANALYST_NAME', 'analyst-1')
    monkeypatch.setenv('AEGIS_ALLOW_LEGACY_COLLECTOR_TOKEN', '1')
    monkeypatch.setattr(api, 'service', DetectionService(SQLiteHistory(path)))
    monkeypatch.setattr(api, 'pii_detector', PIIDetector())
    monkeypatch.setattr(api, 'attack_model', AttackModel())
    monkeypatch.setattr(api, 'codebert_shadow', ShadowModel())
    with TestClient(api.app, base_url='https://testserver') as client:
        yield client


@pytest.mark.parametrize(('count', 'ids_per_alert'), [(9999, 3), (10000, 3), (10001, 3), (9000, 30)])
def test_old_unrelated_alert_volume_no_longer_blocks_collection(tmp_path, monkeypatch, count, ids_per_alert):
    path = tmp_path / 'history.sqlite3'
    make_v4(path, count, ids_per_alert, approved=True)
    with sqlite3.connect(path) as db:
        n, size = db.execute('SELECT count(*),sum(length(event_ids)) FROM stream_alerts').fetchone()
        old = db.execute('SELECT payload,approval FROM detections WHERE detection_id=?', ('old-alert-0',)).fetchone()
    assert n == count
    if ids_per_alert == 30:
        assert count < 10001 and size > 8 * 1024 * 1024
    with client_at(path, monkeypatch) as client:
        rows = [event(50000 + i, i, f'198.51.100.{i+1}') for i in range(3)]
        response = send(client, 'fresh-window', rows)
        assert response.status_code == 200, response.text
        assert response.json()['summary']['processed'] == 3
        replay = send(client, 'fresh-replay', rows)
        assert replay.status_code == 200 and replay.json()['summary']['duplicate'] == 3
        with sqlite3.connect(path) as db:
            assert db.execute('PRAGMA user_version').fetchone()[0] == 5
            assert db.execute('SELECT count(*) FROM stream_alerts').fetchone()[0] == count + 1
            assert db.execute('SELECT payload,approval FROM detections WHERE detection_id=?', ('old-alert-0',)).fetchone() == old


def test_missing_historical_event_aborts_migration_without_touching_v4(tmp_path):
    path = tmp_path / 'history.sqlite3'
    make_v4(path, missing=True, approved=True)
    with sqlite3.connect(path) as db:
        before = db.execute('SELECT * FROM stream_alerts').fetchall()
        old = db.execute('SELECT payload,approval FROM detections').fetchall()
    with pytest.raises(HistoryError):
        SQLiteHistory(path).list_snapshot()
    with sqlite3.connect(path) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 4
        assert db.execute('SELECT * FROM stream_alerts').fetchall() == before
        assert db.execute('SELECT payload,approval FROM detections').fetchall() == old
        assert not db.execute("SELECT 1 FROM sqlite_master WHERE name='stream_alert_spans'").fetchall()


def test_migration_accepts_same_ids_in_different_order_without_rewriting_history(tmp_path):
    path = tmp_path / 'history.sqlite3'
    make_v4(path, approved=True)
    with sqlite3.connect(path) as db:
        payload = json.loads(db.execute('SELECT payload FROM detections').fetchone()[0])
        payload['event_ids'].reverse()
        db.execute('UPDATE detections SET payload=?', (json.dumps(payload),))
        before = db.execute('SELECT payload,approval FROM detections').fetchone()
    SQLiteHistory(path).list_snapshot()
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT payload,approval FROM detections').fetchone() == before
        assert db.execute('PRAGMA user_version').fetchone()[0] == 5


def test_missing_auth_table_aborts_migration_without_creating_new_version(tmp_path):
    path = tmp_path / 'history.sqlite3'
    make_v4(path, approved=True)
    with sqlite3.connect(path) as db:
        db.execute('DROP TABLE auth_correlation_alerts')
        before = db.execute('SELECT payload,approval FROM detections').fetchall()
    with pytest.raises(HistoryError):
        SQLiteHistory(path).list_snapshot()
    with sqlite3.connect(path) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 4
        assert db.execute('SELECT payload,approval FROM detections').fetchall() == before
        assert not db.execute("SELECT 1 FROM sqlite_master WHERE name='stream_alert_spans'").fetchall()


@pytest.mark.parametrize('damage', ['missing-detection', 'mismatched-ids', 'invalid-approval'])
def test_damaged_alert_payload_or_approval_rolls_back_migration(tmp_path, damage):
    path = tmp_path / 'history.sqlite3'
    make_v4(path, approved=True)
    with sqlite3.connect(path) as db:
        if damage == 'missing-detection':
            db.execute('DELETE FROM detections WHERE detection_id=?', ('old-alert-0',))
        elif damage == 'mismatched-ids':
            payload = json.loads(db.execute('SELECT payload FROM detections').fetchone()[0])
            payload['event_ids'] = ['synthetic-different-id']
            db.execute('UPDATE detections SET payload=?', (json.dumps(payload),))
        else:
            db.execute('UPDATE detections SET approval=?', ('{invalid synthetic json',))
        before_alerts = db.execute('SELECT * FROM stream_alerts').fetchall()
        before_detections = db.execute('SELECT * FROM detections').fetchall()
    with pytest.raises(HistoryError):
        SQLiteHistory(path).list_snapshot()
    with sqlite3.connect(path) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 4
        assert db.execute('SELECT * FROM stream_alerts').fetchall() == before_alerts
        assert db.execute('SELECT * FROM detections').fetchall() == before_detections
        assert not db.execute("SELECT 1 FROM sqlite_master WHERE name IN ('stream_alert_spans','stream_host_event_id')").fetchall()


def test_late_event_compares_migrated_approved_alert_and_survives_restart(tmp_path, monkeypatch):
    path = tmp_path / 'history.sqlite3'
    ids = make_v4(path, approved=True)
    with sqlite3.connect(path) as db:
        before = db.execute('SELECT payload,approval FROM detections WHERE detection_id=?', ('old-alert-0',)).fetchone()
    with client_at(path, monkeypatch) as client:
        late = event(70000, 0, '198.51.100.8')
        late['EventData']['UtcTime'] = '2025-01-01 00:00:01.500000'
        result = send(client, 'late', [late])
        assert result.status_code == 200, result.text
        api.service = DetectionService(SQLiteHistory(path))
        replay = send(client, 'late-replay', [late])
        assert replay.status_code == 200 and replay.json()['summary']['duplicate'] == 1
        with sqlite3.connect(path) as db:
            assert db.execute('SELECT payload,approval FROM detections WHERE detection_id=?', ('old-alert-0',)).fetchone() == before
            new = db.execute('SELECT event_ids FROM stream_alerts WHERE detection_id!=?', ('old-alert-0',)).fetchall()
            assert len(new) == 1
            assert set(ids) < set(json.loads(new[0][0]))


def test_migration_is_safe_when_instances_open_concurrently(tmp_path):
    path = tmp_path / 'history.sqlite3'
    make_v4(path, count=20, approved=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        result = list(pool.map(lambda _: SQLiteHistory(path).list_snapshot(), range(4)))
    assert all(len(detections) == 20 for _, detections in result)
    assert all(next(d for d in detections if d['detection_id'] == 'old-alert-0')['approval']['simulation_only']
               for _, detections in result)
    with sqlite3.connect(path) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 5
        assert db.execute('SELECT count(*) FROM stream_alert_spans').fetchone()[0] == 20


def test_locked_migration_is_atomic_and_retries_after_lock_release(tmp_path):
    path = tmp_path / 'history.sqlite3'
    make_v4(path, count=20, approved=True)
    store = SQLiteHistory(path, timeout=0.01)
    with sqlite3.connect(path, isolation_level=None) as blocker:
        blocker.execute('BEGIN IMMEDIATE')
        with pytest.raises(HistoryError):
            store.list_snapshot()
        assert blocker.execute('PRAGMA user_version').fetchone()[0] == 4
        assert not blocker.execute("SELECT 1 FROM sqlite_master WHERE name='stream_alert_spans'").fetchall()
        blocker.execute('ROLLBACK')
    _, detections = store.list_snapshot()
    assert len(detections) == 20
    assert any(item.get('approval', {}).get('simulation_only') for item in detections)
    with sqlite3.connect(path) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 5
        assert db.execute('SELECT count(*) FROM stream_alert_spans').fetchone()[0] == 20


def test_fanout_span_query_uses_collector_host_time_index(tmp_path):
    path = tmp_path / 'history.sqlite3'
    make_v4(path)
    SQLiteHistory(path).list_snapshot()
    with sqlite3.connect(path) as db:
        plan = db.execute('EXPLAIN QUERY PLAN SELECT detection_id FROM stream_alert_spans '
                          'WHERE collector_id=? AND host_key=? AND start_us>=? AND start_us<=? AND end_us>=?',
                          ('collector-a', host_key(), 0, 10, 0)).fetchall()
    assert any('fanout_alert_time' in str(row) and 'SEARCH' in str(row) for row in plan), plan


def test_backfill_plan_probes_event_id_not_all_events_of_host(tmp_path):
    path = tmp_path / 'history.sqlite3'
    make_v4(path)
    SQLiteHistory(path).list_snapshot()
    with sqlite3.connect(path) as db:
        plan = db.execute('EXPLAIN QUERY PLAN SELECT s.event_id,s.occurred '
                          'FROM json_each(?) AS j CROSS JOIN stream_events AS s '
                          'INDEXED BY stream_host_event_id '
                          'WHERE s.collector_id=? AND s.host_key=? AND s.event_id=j.value',
                          ('["synthetic"]', 'collector-a', host_key())).fetchall()
    assert any('stream_host_event_id' in str(row) and 'event_id=?' in str(row) for row in plan), plan


def test_concurrent_retries_and_mixed_batches_are_atomic_after_migration(tmp_path, monkeypatch):
    path = tmp_path / 'history.sqlite3'
    make_v4(path, approved=True)
    with client_at(path, monkeypatch) as client:
        # Finish the one-time migration before testing simultaneous ingestion.
        api.service.history.list_collectors()
        original = [event(90000 + i, i, f'198.51.100.{i+1}') for i in range(3)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(lambda _: send(client, 'same-key', original), range(4)))
        assert all(r.status_code == 200 for r in responses), [r.text for r in responses]
        assert sum(not r.json()['replayed'] for r in responses) == 1
        def mixed(i):
            new = event(91000 + i, 3 + i, f'198.51.100.{10 + i}')
            return send(client, f'mixed-{i}', [original[0], new])
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            mixed_responses = list(pool.map(mixed, range(4)))
        assert all(r.status_code == 200 for r in mixed_responses), [r.text for r in mixed_responses]
        assert all(r.json()['summary']['duplicate'] == 1 and r.json()['summary']['processed'] == 1
                   for r in mixed_responses)
        with sqlite3.connect(path) as db:
            assert db.execute('SELECT count(*) FROM stream_events WHERE occurred>=?',
                              ('2026-01-01T00:00:00+00:00',)).fetchone()[0] == 7
            assert db.execute('SELECT count(*) FROM stream_alerts').fetchone()[0] == 2
            assert db.execute('SELECT count(*) FROM collected_batches').fetchone()[0] == 5


def test_far_apart_new_events_do_not_scan_unrelated_fifty_thousand_history_rows(tmp_path, monkeypatch):
    path = tmp_path / 'history.sqlite3'
    make_v4(path, count=0)
    key = host_key()
    with sqlite3.connect(path) as db:
        rows = ((f'unrelated-key-{i}', 'full-v1:' + 'd' * 64, 'collector-a', key,
                 '2022-01-01T00:00:00+00:00', f'dest-{i % 3}', 1,
                 f'unrelated-event-{i}', '[HOST:old]') for i in range(50001))
        db.executemany('INSERT INTO stream_events VALUES (?,?,?,?,?,?,?,?,?)', rows)
    with client_at(path, monkeypatch) as client:
        before = event(93000, 0, '198.51.100.1')
        before['EventData']['UtcTime'] = '2019-01-01 00:00:00.000'
        after = event(93001, 0, '198.51.100.2')
        result = send(client, 'distant', [before, after])
        assert result.status_code == 200, result.text
        assert result.json()['summary']['processed'] == 2
        with sqlite3.connect(path) as db:
            assert db.execute('SELECT count(*) FROM stream_events').fetchone()[0] == 50006


def test_distinct_old_windows_are_indexed_without_blocking_fresh_window(tmp_path, monkeypatch):
    path = tmp_path / 'history.sqlite3'
    make_v4(path, count=0)
    key = host_key()
    origin = datetime(2020, 1, 1, tzinfo=timezone.utc)
    count = 10001
    with sqlite3.connect(path) as db:
        def cases():
            for i in range(count):
                ids = [f'{i+1:08x}-0000-4000-8000-{j:012d}' for j in range(3)]
                yield i, ids, origin + timedelta(minutes=20 * i)
        def records():
            for i, ids, base in cases():
                for j, ident in enumerate(ids):
                    yield (f'distinct-key-{i}-{j}', 'full-v1:' + 'b' * 64, 'collector-a', key,
                           (base + timedelta(minutes=j)).isoformat(), f'dest-{j}', 1, ident, '[HOST:old]')
        db.executemany('INSERT INTO stream_events VALUES (?,?,?,?,?,?,?,?,?)', records())
        def detections():
            for i, ids, _ in cases():
                ident = f'distinct-alert-{i}'
                payload = {'detection_id': ident, 'source': 'correlation', 'technique': 'T1595',
                           'event_ids': ids, 'host': '[HOST:old]', 'evidence': ['old evidence'],
                           'status': 'pending_review'}
                yield (1, ident, json.dumps(payload, separators=(',', ':')), None)
        db.executemany('INSERT INTO detections(analysis_sequence,detection_id,payload,approval) VALUES (?,?,?,?)', detections())
        db.executemany('INSERT INTO stream_alerts VALUES (?,?,?,?)',
                       (('collector-a', key, f'distinct-alert-{i}', json.dumps(ids)) for i, ids, _ in cases()))
    begin = time.perf_counter()
    with client_at(path, monkeypatch) as client:
        rows = [event(80000 + i, i, f'198.51.100.{i+1}') for i in range(3)]
        result = send(client, 'new-years-later', rows)
        elapsed = time.perf_counter() - begin
        assert result.status_code == 200, result.text
        with sqlite3.connect(path) as db:
            assert db.execute('SELECT count(*) FROM stream_alerts').fetchone()[0] == count + 1
            assert db.execute('SELECT count(*) FROM stream_alert_spans').fetchone()[0] == count + 1
    # Informational measurement only; no brittle hardware-dependent cutoff.
    print(f'v4 migration + API: {count} distinct alerts, {count * 3} indexed events, {elapsed:.3f}s')
