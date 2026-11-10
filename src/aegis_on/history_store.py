"""Transactional storage for already-sanitized analysis results.

Callers must remove raw events and apply their display privacy policy before
calling this module. This layer does not inspect or sanitize its inputs.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
from threading import Lock
from typing import Any, Iterator


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
                elif version != 2:
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
            if collection is not None:
                row = conn.execute('SELECT c.input_type,c.digest,a.payload FROM collected_batches c '
                                   'JOIN analyses a ON a.sequence=c.analysis_sequence '
                                   'WHERE c.collector_id=? AND c.batch_id=?',
                                   (collection['collector_id'], collection['batch_id'])).fetchone()
                if row is not None:
                    if row[0] != collection['input_type'] or row[1] != collection['digest']:
                        raise BatchConflict()
                    saved = json.loads(row[2])
                    conn.execute('COMMIT')
                    return {'analysis_id': saved['analysis_id'], 'summary': saved['summary'], 'replayed': True}
            sequence = conn.execute('INSERT INTO analyses(payload) VALUES (?)', (encoded_batch,)).lastrowid
            conn.executemany('INSERT INTO detections(analysis_sequence,detection_id,payload) VALUES (?,?,?)',
                             [(sequence, detection_id, payload) for detection_id, payload in encoded_detections])
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
            row = conn.execute('SELECT c.input_type,c.digest,a.payload FROM collected_batches c '
                               'JOIN analyses a ON a.sequence=c.analysis_sequence '
                               'WHERE c.collector_id=? AND c.batch_id=?',
                               (collection['collector_id'], collection['batch_id'])).fetchone()
            if row is None:
                return None
            if row[0] != collection['input_type'] or row[1] != collection['digest']:
                raise BatchConflict()
            saved = json.loads(row[2])
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
