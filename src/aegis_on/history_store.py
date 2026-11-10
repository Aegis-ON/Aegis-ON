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
                    conn.execute('PRAGMA user_version = 1')
                elif version != 1:
                    raise HistoryError('History storage unavailable')
                conn.execute('COMMIT')
                self._pending_identity = None
            yield conn
        except KeyError:
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

    def save_analysis(self, batch: dict[str, Any], detections: list[dict[str, Any]]) -> None:
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
            sequence = conn.execute('INSERT INTO analyses(payload) VALUES (?)', (encoded_batch,)).lastrowid
            conn.executemany('INSERT INTO detections(analysis_sequence,detection_id,payload) VALUES (?,?,?)',
                             [(sequence, detection_id, payload) for detection_id, payload in encoded_detections])
            conn.execute('COMMIT')

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
