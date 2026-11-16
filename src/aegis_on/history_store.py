"""Transactional storage for already-sanitized analysis results.

Callers must remove raw events and apply their display privacy policy before
calling this module. This layer does not inspect or sanitize its inputs.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import json
import hashlib
import hmac
import os
import secrets
import stat
import tempfile
from pathlib import Path
import sqlite3
from threading import Lock
from typing import Any, Iterator
from uuid import uuid4


class HistoryError(Exception):
    """A storage failure whose message does not disclose paths or data."""


class BatchConflict(Exception):
    """An idempotency key was reused for different input."""


def _encode(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(',', ':'))


class SQLiteHistory:
    """A file-backed history with a fresh connection for each operation.

    ``save_analysis`` accepts a sanitized batch dictionary and sanitized
    detection dictionaries. A detection must have a unique string
    ``detection_id`` and an evidence list. ``list_detections`` and ``approve``
    add an ``approval`` field only after its first simulated approval.
    """

    def __init__(self, path: str | os.PathLike[str], *, timeout: float = 5.0) -> None:
        self.path = os.fspath(path)
        self.timeout = timeout
        self._identity = None
        # Only an inode created exclusively by this instance can be retried
        # after a transient initialization failure. Existing empty files must
        # remain errors, since they might contain a truncated history.
        self._pending_identity = None
        self._identity_lock = Lock()
        if not self.path or self.path == ':memory:':
            raise HistoryError('History storage unavailable')

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        conn = None
        try:
            # Do not alter existing directory permissions. Create each missing
            # component privately, including parents of a configured DB path.
            parent = Path(self.path).parent
            missing = []
            while not parent.exists():
                missing.append(parent)
                parent = parent.parent
            for directory in reversed(missing):
                directory.mkdir(mode=0o700, exist_ok=True)
            # Create new database files privately without altering existing files.
            with self._identity_lock:
                if self._identity is not None and not os.path.exists(self.path):
                    raise HistoryError('History storage unavailable')
                created = False
                try:
                    fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                except FileExistsError:
                    pass
                else:
                    os.close(fd)
                    created = True
                if os.path.islink(self.path):
                    raise HistoryError('History storage unavailable')
                st = os.stat(self.path)
                if os.name == 'posix' and st.st_mode & 0o077:
                    raise HistoryError('History storage unavailable')
                identity = (st.st_dev, st.st_ino)
                if self._identity is not None and self._identity != identity:
                    raise HistoryError('History storage unavailable')
                self._identity = identity
                if created:
                    self._pending_identity = identity
                conn = sqlite3.connect(self.path, timeout=self.timeout, isolation_level=None)
                conn.execute('PRAGMA foreign_keys = ON')
                # Keep the pending-creation decision and initialization in the
                # same lock; SQLite also serializes across separate processes.
                conn.execute('BEGIN IMMEDIATE')
                version = conn.execute('PRAGMA user_version').fetchone()[0]
                if version == 0:
                    if self._pending_identity != identity:
                        raise HistoryError('History storage unavailable')
                    objects = conn.execute(
                        "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' LIMIT 1"
                    ).fetchone()
                    if objects:
                        raise HistoryError('History storage unavailable')
                    conn.execute('CREATE TABLE analyses (sequence INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL)')
                    conn.execute('CREATE TABLE detections (sequence INTEGER PRIMARY KEY AUTOINCREMENT, '
                                 'analysis_sequence INTEGER NOT NULL REFERENCES analyses(sequence), '
                                 'detection_id TEXT NOT NULL UNIQUE, payload TEXT NOT NULL, approval TEXT)')
                    version = 1
                if version == 1:
                    # Do not upgrade a damaged v1 file into an apparently
                    # valid but empty v2 database.
                    required = {
                        'analyses': {'sequence', 'payload'},
                        'detections': {'sequence', 'analysis_sequence', 'detection_id', 'payload', 'approval'},
                    }
                    for table, columns in required.items():
                        actual = {row[1] for row in conn.execute(f'PRAGMA table_info({table})')}
                        if not columns.issubset(actual):
                            raise HistoryError('History storage unavailable')
                    conn.execute('CREATE TABLE collectors (collector_id TEXT PRIMARY KEY, last_received_at TEXT, '
                                 'last_heartbeat_at TEXT, reported_state TEXT, last_error_at TEXT, last_error_code TEXT)')
                    conn.execute('CREATE TABLE collected_batches (collector_id TEXT NOT NULL, batch_id TEXT NOT NULL, '
                                 'input_type TEXT NOT NULL, digest TEXT NOT NULL, '
                                 'analysis_sequence INTEGER NOT NULL REFERENCES analyses(sequence), '
                                 'PRIMARY KEY(collector_id,batch_id))')
                    conn.execute('PRAGMA user_version = 2')
                    version = 2
                if version == 2:
                    required_v2 = {
                        'analyses': {'sequence', 'payload'},
                        'detections': {'sequence', 'analysis_sequence', 'detection_id', 'payload', 'approval'},
                        'collectors': {'collector_id', 'last_received_at', 'last_heartbeat_at', 'reported_state', 'last_error_at', 'last_error_code'},
                        'collected_batches': {'collector_id', 'batch_id', 'input_type', 'digest', 'analysis_sequence'},
                    }
                    for table, columns in required_v2.items():
                        if not columns.issubset({row[1] for row in conn.execute(f'PRAGMA table_info({table})')}):
                            raise HistoryError('History storage unavailable')
                    conn.execute('CREATE TABLE stream_events (event_key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, '
                                 'collector_id TEXT NOT NULL, host_key TEXT NOT NULL, occurred TEXT NOT NULL, '
                                 'destination_key TEXT, outbound INTEGER NOT NULL, event_id TEXT NOT NULL, '
                                 'host_display TEXT NOT NULL)')
                    conn.execute('CREATE INDEX stream_host_time ON stream_events(collector_id,host_key,occurred)')
                    conn.execute('CREATE TABLE stream_alerts (collector_id TEXT NOT NULL, host_key TEXT NOT NULL, '
                                 'detection_id TEXT NOT NULL UNIQUE REFERENCES detections(detection_id), '
                                 'event_ids TEXT NOT NULL)')
                    conn.execute('PRAGMA user_version = 3')
                    version = 3
                if version == 3:
                    required_v3 = {
                        'analyses': {'sequence', 'payload'},
                        'detections': {'sequence', 'analysis_sequence', 'detection_id', 'payload', 'approval'},
                        'collectors': {'collector_id', 'last_received_at', 'last_heartbeat_at', 'reported_state', 'last_error_at', 'last_error_code'},
                        'collected_batches': {'collector_id', 'batch_id', 'input_type', 'digest', 'analysis_sequence'},
                        'stream_events': {'event_key', 'fingerprint', 'collector_id', 'host_key', 'occurred', 'destination_key', 'outbound', 'event_id', 'host_display'},
                        'stream_alerts': {'collector_id', 'host_key', 'detection_id', 'event_ids'},
                    }
                    for table, columns in required_v3.items():
                        if not columns.issubset({row[1] for row in conn.execute(f'PRAGMA table_info({table})')}):
                            raise HistoryError('History storage unavailable')
                    conn.execute('CREATE TABLE auth_correlation_meta (key_id TEXT NOT NULL)')
                    conn.execute('CREATE TABLE auth_correlation_events (event_key TEXT PRIMARY KEY REFERENCES stream_events(event_key), '
                                 'group_key TEXT NOT NULL, occurred TEXT NOT NULL, outcome TEXT NOT NULL, '
                                 'event_id TEXT NOT NULL, host_display TEXT NOT NULL)')
                    conn.execute('CREATE INDEX auth_group_time ON auth_correlation_events(group_key,occurred)')
                    conn.execute('CREATE TABLE auth_correlation_alerts (success_key TEXT NOT NULL, '
                                 'detection_id TEXT NOT NULL UNIQUE REFERENCES detections(detection_id))')
                    conn.execute('PRAGMA user_version = 4')
                    version = 4
                if version != 4:
                    raise HistoryError('History storage unavailable')
                conn.execute('COMMIT')
                self._pending_identity = None
            yield conn
        except (KeyError, BatchConflict):
            if conn is not None and conn.in_transaction:
                conn.rollback()
            raise
        except Exception:
            if conn is not None and conn.in_transaction:
                try:
                    conn.rollback()
                except sqlite3.Error:
                    pass
            raise HistoryError('History storage unavailable') from None
        finally:
            if conn is not None:
                conn.close()

    @staticmethod
    def _decode_detection(payload: str, approval: str | None) -> dict[str, Any]:
        detection = json.loads(payload)
        if not isinstance(detection, dict):
            raise ValueError('invalid stored detection')
        if approval is not None:
            data = json.loads(approval)
            if not isinstance(data, dict):
                raise ValueError('invalid stored approval')
            detection['approval'] = data
        return detection

    def _auth_key(self, conn) -> bytes:
        """Keep correlation key separate from SQLite; never silently replace it."""
        path = self.path + '.correlation-key'
        existing = conn.execute('SELECT key_id FROM auth_correlation_meta').fetchall()
        if len(existing) > 1:
            raise HistoryError('Correlation key unavailable')
        if not existing:
            try:
                os.lstat(path)
            except FileNotFoundError:
                fd, temporary = tempfile.mkstemp(prefix='.aegis-correlation-', dir=str(Path(path).parent))
                try:
                    key = secrets.token_bytes(32)
                    if os.write(fd, key) != len(key):
                        raise HistoryError('Correlation key unavailable')
                    os.fsync(fd)
                    try:
                        os.link(temporary, path)
                    except FileExistsError:
                        pass
                finally:
                    os.close(fd)
                    os.unlink(temporary)
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode):
            raise HistoryError('Correlation key unavailable')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            info = os.fstat(fd)
            if ((info.st_dev, info.st_ino) != (before.st_dev, before.st_ino) or
                    not stat.S_ISREG(info.st_mode) or (os.name == 'posix' and info.st_mode & 0o077)):
                raise HistoryError('Correlation key unavailable')
            key = os.read(fd, 33)
            if len(key) != 32:
                raise HistoryError('Correlation key unavailable')
        finally:
            os.close(fd)
        key_id = hmac.new(key, b'aegis-auth-correlation-key-v1', hashlib.sha256).hexdigest()
        if existing:
            if not hmac.compare_digest(existing[0][0], key_id):
                raise HistoryError('Correlation key unavailable')
        else:
            conn.execute('INSERT INTO auth_correlation_meta VALUES (?)', (key_id,))
        return key

    @staticmethod
    def _auth_correlate(conn, sequence, batch, changed):
        """Re-evaluate only windows affected by newly indexed auth observations."""
        intervals = set()
        for item in changed:
            when = datetime.fromisoformat(item['occurred'])
            intervals.add((item['group_key'], when - timedelta(minutes=10), when, when + timedelta(minutes=10)))
        evaluated_successes = set()
        for group, start, lower, upper in intervals:
            rows = conn.execute(
                'SELECT event_key,occurred,outcome,event_id,host_display FROM auth_correlation_events '
                'WHERE group_key=? AND occurred>=? AND occurred<=? ORDER BY occurred,event_key LIMIT 5001',
                (group, start.isoformat(), upper.isoformat())).fetchall()
            if len(rows) > 5000:
                raise HistoryError('Authentication correlation window too large')
            failures = []
            for event_key, occurred, outcome, event_id, host in rows:
                when = datetime.fromisoformat(occurred)
                failures = [f for f in failures if when - f[0] <= timedelta(minutes=10)]
                if outcome == 'failure':
                    failures.append((when, event_id))
                    continue
                if when < lower:
                    continue
                if event_key in evaluated_successes:
                    continue
                evaluated_successes.add(event_key)
                earlier = [(t, e) for t, e in failures if t < when]
                if len(earlier) < 3:
                    continue
                ids = [e for _, e in earlier] + [event_id]
                evidence = ['At least three failures followed by success within ten minutes',
                            f'observed period: {earlier[0][0].isoformat()} to {occurred}',
                            'same collector, reported host, account and source address; may span batches',
                            'Shared addresses or routine activity do not prove a common device or attack',
                            'Process and network stages are not linked: trusted identity mapping unavailable']
                row = conn.execute('SELECT d.detection_id,d.payload,d.approval FROM auth_correlation_alerts a '
                                   'JOIN detections d ON d.detection_id=a.detection_id '
                                   'WHERE a.success_key=? ORDER BY d.sequence DESC LIMIT 1', (event_key,)).fetchone()
                if row is None:
                    # A v3 same-batch alert may already exist for a replayed success.
                    for old_id, payload, approval in conn.execute(
                            'SELECT detection_id,payload,approval FROM detections WHERE payload LIKE ?',
                            ('%' + event_id + '%',)):
                        old = json.loads(payload)
                        if old.get('technique') == 'authentication-review' and event_id in old.get('event_ids', []):
                            row = (old_id, payload, approval)
                            conn.execute('INSERT INTO auth_correlation_alerts VALUES (?,?)', (event_key, old_id))
                            break
                if row:
                    old = json.loads(row[1])
                    if set(old.get('event_ids', [])) == set(ids):
                        continue
                    if row[2] is None:
                        old.update(event_ids=ids, evidence=evidence)
                        conn.execute('UPDATE detections SET payload=? WHERE detection_id=?', (_encode(old), row[0]))
                        continue
                detection_id = str(uuid4())
                alert = {'technique': 'authentication-review', 'title': 'Repeated authentication failures followed by success',
                         'score': 55, 'source': 'correlation', 'event_ids': ids, 'host': host,
                         'status': 'pending_review', 'requires_human_approval': False,
                         'detection_id': detection_id, 'evidence': evidence}
                conn.execute('INSERT INTO detections(analysis_sequence,detection_id,payload) VALUES (?,?,?)',
                             (sequence, detection_id, _encode(alert)))
                conn.execute('INSERT INTO auth_correlation_alerts VALUES (?,?)', (event_key, detection_id))
                batch['detection_ids'].append(detection_id)

    @staticmethod
    def _auth_index(conn, stream, key, batch):
        changed = []
        display_sources = {source['event_id']: source for source in batch['source_events']}
        for item in stream:
            group_key = hmac.new(key, ('auth-group-v1:' + item['auth_group']).encode(), hashlib.sha256).hexdigest()
            source = display_sources.get(item['event_id'])
            if source is not None:
                source['auth_correlation_group'] = '[AUTH-GROUP:' + group_key[:16] + ']'
            cursor = conn.execute('INSERT OR IGNORE INTO auth_correlation_events VALUES (?,?,?,?,?,?)',
                                  (item['event_key'], group_key, item['occurred'], item['auth_outcome'],
                                   item['event_id'], item['host_display']))
            if cursor.rowcount:
                changed.append({'group_key': group_key, 'occurred': item['occurred']})
        return changed

    @staticmethod
    def _stream_fanout(conn, sequence, batch, collection, novel):
        """Correlate sanitized event identities in an atomic SQLite transaction.

        Only outbound ID 3 events participate. No raw host, address or command
        is retained. Late events are sorted by occurrence time, not arrival time.
        """
        hosts = {item['host_key'] for item in novel if item['outbound'] and item['destination_key']}
        for host_key in hosts:
            times = [datetime.fromisoformat(item['occurred']) for item in novel
                     if item['host_key'] == host_key and item['outbound'] and item['destination_key']]
            try:
                lower, upper = min(times) - timedelta(minutes=10), max(times) + timedelta(minutes=10)
            except OverflowError:
                raise HistoryError('History storage unavailable') from None
            rows = conn.execute('SELECT occurred,destination_key,event_id,host_display FROM stream_events '
                                'WHERE collector_id=? AND host_key=? AND outbound=1 '
                                'AND occurred>=? AND occurred<=? ORDER BY occurred,event_id LIMIT 50001',
                                (collection['collector_id'], host_key, lower.isoformat(), upper.isoformat())).fetchall()
            # Fail closed rather than silently omit evidence in a pathological window.
            if len(rows) > 50000:
                raise HistoryError('History storage unavailable')
            existing = conn.execute('SELECT detection_id,event_ids FROM stream_alerts '
                                    'WHERE collector_id=? AND host_key=? ORDER BY rowid DESC LIMIT 10001',
                                    (collection['collector_id'], host_key)).fetchall()
            if len(existing) > 10000 or sum(len(ids) for _, ids in existing) > 8 * 1024 * 1024:
                raise HistoryError('History storage unavailable')
            alerts = [(d, set(json.loads(ids))) for d, ids in existing]
            novel_ids = {item['event_id'] for item in novel if item['host_key'] == host_key
                         and item['outbound'] and item['destination_key']}
            index = end = novel_count = work = mutations = 0
            last_end = -1
            counts = {}
            while index < len(rows):
                start = datetime.fromisoformat(rows[index][0])
                while end < len(rows) and datetime.fromisoformat(rows[end][0]) - start <= timedelta(minutes=10):
                    destination = rows[end][1]
                    counts[destination] = counts.get(destination, 0) + 1
                    novel_count += rows[end][2] in novel_ids
                    end += 1
                # With an unchanged right edge this is a subset of the prior
                # window; it cannot add evidence or satisfy a new condition.
                if end != last_end and len(counts) >= 3 and novel_count:
                    # Bound work and alert amplification; fail the complete batch
                    # rather than acknowledge only a portion of its evidence.
                    work += (end - index) * (len(alerts) + 1)
                    if work > 250000:
                        raise HistoryError('History storage unavailable')
                    window = rows[index:end]
                    ids = [r[2] for r in window]
                    id_set = set(ids)
                    # An existing superset already represents this exact window.
                    covered = any(id_set <= old_ids for _, old_ids in alerts)
                    if not covered:
                        candidates = [(d, old_ids) for d, old_ids in alerts if old_ids < id_set]
                        candidates.sort(key=lambda pair: len(pair[1]), reverse=True)
                        match = None
                        old = None
                        for candidate, _ in candidates:
                            row = conn.execute('SELECT payload,approval FROM detections WHERE detection_id=?', (candidate,)).fetchone()
                            if row is None:
                                raise HistoryError('History storage unavailable')
                            payload = json.loads(row[0])
                            if row[1] is None and payload.get('status') != 'approved_for_simulated_response':
                                match, old = candidate, payload
                                break
                        evidence = [f'{len(counts)} unique destinations in ten minutes',
                                    f'observed period: {window[0][0]} to {window[-1][0]}',
                                    f'related connection events: {len(window)}',
                                    'condition: same collector and reported host, at least 3 unique destinations within 10 minutes, outbound connections only',
                                    'host-level observation; processes, source addresses and actual device identity are not asserted to be the same',
                                    'multiple connections are not proof of scanning or attack']
                        mutations += 1
                        if mutations > 1000:
                            raise HistoryError('History storage unavailable')
                        if match:
                            old.update(score=min(85,48+8*len(counts)), evidence=evidence, event_ids=ids)
                            conn.execute('UPDATE detections SET payload=? WHERE detection_id=?', (_encode(old),match))
                            conn.execute('UPDATE stream_alerts SET event_ids=? WHERE detection_id=?', (_encode(ids),match))
                            alerts = [(d, id_set if d == match else old_ids) for d, old_ids in alerts]
                        else:
                            detection_id = str(uuid4())
                            detection = {'technique':'T1595', 'title':'Potential multiple-destination connections',
                                         'score':min(85,48+8*len(counts)), 'source':'correlation',
                                         'evidence':evidence, 'event_ids':ids, 'host':window[0][3],
                                         'requires_human_approval':False, 'status':'pending_review',
                                         'detection_id':detection_id}
                            conn.execute('INSERT INTO detections(analysis_sequence,detection_id,payload) VALUES (?,?,?)',
                                         (sequence,detection_id,_encode(detection)))
                            conn.execute('INSERT INTO stream_alerts VALUES (?,?,?,?)',
                                         (collection['collector_id'],host_key,detection_id,_encode(ids)))
                            batch['detection_ids'].append(detection_id)
                            alerts.append((detection_id,id_set))
                last_end = end
                # All events at the same occurrence time form one boundary;
                # their random display IDs never imply an ordering.
                while index < end:
                    if datetime.fromisoformat(rows[index][0]) != start:
                        break
                    destination = rows[index][1]
                    counts[destination] -= 1
                    if counts[destination] == 0:
                        del counts[destination]
                    novel_count -= rows[index][2] in novel_ids
                    index += 1

    def save_analysis(self, batch: dict[str, Any], detections: list[dict[str, Any]], collection: dict[str, str] | None = None) -> dict[str, Any] | None:
        try:
            if not isinstance(batch, dict) or not isinstance(detections, list):
                raise ValueError('invalid analysis')
            encoded_batch = _encode(batch)
            encoded_detections = []
            for detection in detections:
                if not isinstance(detection, dict):
                    raise ValueError('invalid detection')
                detection_id = detection.get('detection_id')
                if (not isinstance(detection_id, str) or not detection_id
                        or not isinstance(detection.get('evidence'), list)
                        or 'approval' in detection):
                    raise ValueError('invalid detection')
                encoded_detections.append((detection_id, _encode(detection)))
        except Exception:
            raise HistoryError('History storage unavailable') from None
        with self._connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            auth_key = self._auth_key(conn) if collection and collection['input_type'] == 'auth' else None
            if collection is not None:
                row = conn.execute('SELECT c.input_type,c.digest,a.payload,c.analysis_sequence FROM collected_batches c '
                                   'JOIN analyses a ON a.sequence=c.analysis_sequence '
                                   'WHERE c.collector_id=? AND c.batch_id=?',
                                   (collection['collector_id'], collection['batch_id'])).fetchone()
                if row is not None:
                    if row[0] != collection['input_type'] or row[1] not in (collection['digest'], collection.get('legacy_digest')):
                        raise BatchConflict()
                    saved = json.loads(row[2])
                    if collection.get('legacy_reindex'):
                        stream = collection['events']
                        for item in stream:
                            previous = conn.execute('SELECT fingerprint FROM stream_events WHERE event_key=?', (item['event_key'],)).fetchone()
                            legacy = item['fingerprint']
                            secure = 'hmac-v2:' + hmac.new(auth_key, ('auth-record-v2:' + legacy).encode(), hashlib.sha256).hexdigest()
                            if not previous or previous[0] not in (legacy, secure):
                                raise BatchConflict()
                            if previous[0] == legacy:
                                conn.execute('UPDATE stream_events SET fingerprint=? WHERE event_key=?', (secure, item['event_key']))
                        changed = self._auth_index(conn, stream, auth_key, saved)
                        self._auth_correlate(conn, row[3], saved, changed)
                        conn.execute('UPDATE analyses SET payload=? WHERE sequence=?', (_encode(saved), row[3]))
                        conn.execute('UPDATE collected_batches SET digest=? WHERE collector_id=? AND batch_id=?',
                                     (collection['digest'], collection['collector_id'], collection['batch_id']))
                    conn.execute('COMMIT')
                    return {'analysis_id': saved['analysis_id'], 'summary': saved['summary'], 'replayed': True}
            stream = collection.get('events') if collection else None
            novel = []
            if stream is not None:
                duplicate_ids = set()
                for item in stream:
                    previous = conn.execute('SELECT fingerprint FROM stream_events WHERE event_key=?',
                                            (item['event_key'],)).fetchone()
                    if previous:
                        legacy = item['fingerprint']
                        secure = ('hmac-v2:' + hmac.new(auth_key, ('auth-record-v2:' + legacy).encode(), hashlib.sha256).hexdigest()) if auth_key else legacy
                        if previous[0] not in (legacy, secure):
                            raise BatchConflict()
                        if auth_key and previous[0] == legacy:
                            conn.execute('UPDATE stream_events SET fingerprint=? WHERE event_key=?', (secure, item['event_key']))
                        duplicate_ids.add(item['event_id'])
                    else:
                        if auth_key:
                            item['fingerprint'] = 'hmac-v2:' + hmac.new(auth_key, ('auth-record-v2:' + item['fingerprint']).encode(), hashlib.sha256).hexdigest()
                        novel.append(item)
                batch['source_events'] = [s for s in batch['source_events'] if s['event_id'] not in duplicate_ids]
                batch['event_refs'] = [s for s in batch['event_refs'] if s['event_id'] not in duplicate_ids]
                batch['attack_model']['results'] = [s for s in batch['attack_model']['results'] if s['event_id'] not in duplicate_ids]
                detections = [d for d in detections if (collection['input_type'] == 'auth' or d['source'] != 'correlation') and
                              not any(i in duplicate_ids for i in d['event_ids'])]
                shadow = batch.get('review_shadow')
                if shadow is not None:
                    retained = {d['detection_id'] for d in detections}
                    shadow['events'] = [event for event in shadow['events'] if event['event_id'] not in duplicate_ids]
                    for key in ('current_order', 'proposed_order'):
                        shadow[key] = [detection_id for detection_id in shadow[key] if detection_id in retained]
                batch['summary']['duplicate'] = len(duplicate_ids)
                batch['summary']['processed'] = len(novel)
                batch['detection_ids'] = [d['detection_id'] for d in detections]
                encoded_batch = _encode(batch)
                encoded_detections = [(d['detection_id'], _encode(d)) for d in detections]
            sequence = conn.execute('INSERT INTO analyses(payload) VALUES (?)', (encoded_batch,)).lastrowid
            conn.executemany('INSERT INTO detections(analysis_sequence,detection_id,payload) VALUES (?,?,?)',
                             [(sequence, detection_id, payload) for detection_id, payload in encoded_detections])
            if stream is not None:
                for item in novel:
                    conn.execute('INSERT INTO stream_events VALUES (?,?,?,?,?,?,?,?,?)',
                                 (item['event_key'], item['fingerprint'], collection['collector_id'],
                                  item['host_key'], item['occurred'], item['destination_key'],
                                  item['outbound'], item['event_id'], item['host_display']))
                self._stream_fanout(conn, sequence, batch, collection, novel)
                if collection['input_type'] == 'auth':
                    changed = self._auth_index(conn, stream, auth_key, batch)
                    self._auth_correlate(conn, sequence, batch, changed)
                conn.execute('UPDATE analyses SET payload=? WHERE sequence=?', (_encode(batch), sequence))
            if collection is not None:
                received = datetime.now(timezone.utc).isoformat()
                conn.execute('INSERT INTO collected_batches(collector_id,batch_id,input_type,digest,analysis_sequence) '
                             'VALUES (?,?,?,?,?)', (collection['collector_id'], collection['batch_id'],
                                                     collection['input_type'], collection['digest'], sequence))
                conn.execute('INSERT INTO collectors(collector_id,last_received_at) VALUES (?,?) '
                             'ON CONFLICT(collector_id) DO UPDATE SET last_received_at=excluded.last_received_at',
                             (collection['collector_id'], received))
            conn.execute('COMMIT')
            if collection is not None:
                return {'analysis_id': batch['analysis_id'], 'summary': batch['summary'], 'replayed': False}

    def heartbeat(self, collector_id: str, state: str, error_code: str | None) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            conn.execute('INSERT INTO collectors(collector_id,last_heartbeat_at,reported_state,last_error_at,last_error_code) '
                         'VALUES (?,?,?,?,?) ON CONFLICT(collector_id) DO UPDATE SET '
                         'last_heartbeat_at=excluded.last_heartbeat_at,reported_state=excluded.reported_state, '
                         'last_error_at=CASE WHEN excluded.last_error_at IS NULL THEN collectors.last_error_at ELSE excluded.last_error_at END, '
                         'last_error_code=CASE WHEN excluded.last_error_code IS NULL THEN collectors.last_error_code ELSE excluded.last_error_code END',
                         (collector_id, now, state, now if state == 'error' else None, error_code))
            conn.execute('COMMIT')

    def lookup_collected(self, collection: dict[str, str]) -> dict[str, Any] | None:
        with self._connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            if collection['input_type'] == 'auth':
                key = self._auth_key(conn)
                collection['legacy_digest'] = collection['digest']
                collection['digest'] = 'hmac-v2:' + hmac.new(key, ('auth-batch-v2:' + collection['digest']).encode(), hashlib.sha256).hexdigest()
            row = conn.execute('SELECT c.input_type,c.digest,a.payload FROM collected_batches c '
                               'JOIN analyses a ON a.sequence=c.analysis_sequence '
                               'WHERE c.collector_id=? AND c.batch_id=?',
                               (collection['collector_id'], collection['batch_id'])).fetchone()
            if row is None:
                conn.execute('COMMIT')
                return None
            if row[0] != collection['input_type'] or row[1] not in (collection['digest'], collection.get('legacy_digest')):
                raise BatchConflict()
            if collection['input_type'] == 'auth' and row[1] == collection.get('legacy_digest'):
                # The authenticated replay supplies the legacy raw records
                # needed to build the new HMAC index in the commit transaction.
                collection['legacy_reindex'] = True
                conn.execute('COMMIT')
                return None
            saved = json.loads(row[2])
            conn.execute('COMMIT')
            return {'analysis_id': saved['analysis_id'], 'summary': saved['summary'], 'replayed': True}

    def list_collectors(self) -> list[dict[str, Any]]:
        with self._connection() as conn:
            names = ('collector_id','last_received_at','last_heartbeat_at','reported_state','last_error_at','last_error_code')
            return [dict(zip(names, row)) for row in conn.execute(
                'SELECT collector_id,last_received_at,last_heartbeat_at,reported_state,last_error_at,last_error_code '
                'FROM collectors ORDER BY collector_id')]

    def list_analyses(self) -> list[dict[str, Any]]:
        with self._connection() as conn:
            output = []
            for (payload,) in conn.execute('SELECT payload FROM analyses ORDER BY sequence DESC'):
                batch = json.loads(payload)
                if not isinstance(batch, dict):
                    raise ValueError('invalid stored analysis')
                output.append(batch)
            return output

    def list_detections(self) -> list[dict[str, Any]]:
        with self._connection() as conn:
            return [self._decode_detection(payload, approval) for payload, approval in
                    conn.execute('SELECT payload,approval FROM detections ORDER BY sequence DESC')]

    def list_snapshot(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        # A single read transaction prevents a concurrent analysis from
        # appearing in detections but not in the corresponding batch list.
        with self._connection() as conn:
            conn.execute('BEGIN')
            analyses = [json.loads(payload) for (payload,) in conn.execute(
                'SELECT payload FROM analyses ORDER BY sequence DESC')]
            if any(not isinstance(batch, dict) for batch in analyses):
                raise ValueError('invalid stored analysis')
            detections = [self._decode_detection(payload, approval) for payload, approval in
                          conn.execute('SELECT payload,approval FROM detections ORDER BY sequence DESC')]
            conn.execute('COMMIT')
            return analyses, detections

    def approve(self, detection_id: str, analyst: str, rationale: str) -> dict[str, Any]:
        with self._connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            row = conn.execute('SELECT payload,approval FROM detections WHERE detection_id = ?',
                               (detection_id,)).fetchone()
            if row is None:
                raise KeyError(detection_id)
            detection = self._decode_detection(*row)
            if row[1] is None:
                if not isinstance(analyst, str) or not isinstance(rationale, str):
                    raise ValueError('invalid approval')
                evidence = detection.get('evidence')
                if not isinstance(evidence, list):
                    raise ValueError('invalid stored evidence')
                now = datetime.now(timezone.utc).isoformat()
                detection['status'] = 'approved_for_simulated_response'
                evidence.append(f'approved locally by {analyst} at {now}')
                if rationale:
                    evidence.append(f'analyst rationale: {rationale}')
                approval = {'simulation_only': True, 'analyst': analyst,
                            'rationale': rationale, 'approved_at': now}
                conn.execute('UPDATE detections SET payload = ?, approval = ? WHERE detection_id = ?',
                             (_encode(detection), _encode(approval), detection_id))
                detection['approval'] = approval
            conn.execute('COMMIT')
            return detection
