"""Explicit per-collector credentials, independent of observed heartbeats.

Secrets are high-entropy machine credentials, not passwords; only their SHA-256
digests are retained. Existing observation rows do not grant access.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import datetime, timezone

from .history_store import SQLiteHistory

_ID = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
_DUMMY = hashlib.sha256(b'aegis-collector-dummy').digest()


class CollectorExists(ValueError):
    """Collector identifier was already registered."""


class CollectorNotFound(ValueError):
    """No registered collector exists for the requested ID."""


class CollectorStateConflict(ValueError):
    """The requested credential transition is no longer valid."""


class CollectorRegistry:
    def __init__(self, history: SQLiteHistory):
        self.history = history

    @staticmethod
    def _table(conn):
        # A separate additive table keeps legacy history schema upgrades intact.
        conn.execute('CREATE TABLE IF NOT EXISTS collector_credentials '
                     '(collector_id TEXT PRIMARY KEY, secret_hash BLOB NOT NULL)')
        columns = {row[1] for row in conn.execute('PRAGMA table_info(collector_credentials)')}
        if columns != {'collector_id', 'secret_hash'}:
            raise ValueError('Invalid collector credential schema')
        conn.execute('CREATE TABLE IF NOT EXISTS collector_credential_changes '
                     '(collector_id TEXT PRIMARY KEY, changed_at TEXT NOT NULL)')
        if {row[1] for row in conn.execute('PRAGMA table_info(collector_credential_changes)')} != {'collector_id', 'changed_at'}:
            raise ValueError('Invalid collector credential change schema')

    @staticmethod
    def _status(value):
        # Existing 32-byte digests remain valid without a history migration.
        # The empty BLOB is an explicit, persistent revoked tombstone.
        if not isinstance(value, bytes) or len(value) not in (0, 32):
            raise ValueError('Invalid collector credential value')
        return 'active' if value else 'revoked'

    def register(self, collector_id: str) -> str:
        if not isinstance(collector_id, str) or not _ID.fullmatch(collector_id):
            raise ValueError('Invalid collector identifier')
        secret = secrets.token_urlsafe(32)
        digest = hashlib.sha256(secret.encode('ascii')).digest()
        with self.history._connection() as conn:
            self._table(conn)
            conn.execute('BEGIN IMMEDIATE')
            # Pre-registration observations are not bound to any machine
            # credential. Do not silently attribute those records to a new PC.
            exists = conn.execute('SELECT 1 FROM collector_credentials WHERE collector_id=? '
                                  'UNION ALL SELECT 1 FROM collectors WHERE collector_id=? LIMIT 1',
                                  (collector_id, collector_id)).fetchone()
            if exists:
                # SQLiteHistory deliberately wraps exceptions; report the conflict
                # after leaving its context so API callers can distinguish it.
                conn.execute('ROLLBACK')
            else:
                conn.execute('INSERT INTO collector_credentials VALUES (?,?)', (collector_id, digest))
                conn.execute('INSERT INTO collector_credential_changes VALUES (?,?)',
                             (collector_id, datetime.now(timezone.utc).isoformat()))
                conn.execute('COMMIT')
        if exists:
            raise CollectorExists('Collector already registered')
        return secret

    def authenticate(self, collector_id: str, secret: str) -> bool:
        return self.authorize(collector_id, secret)

    def authorize(self, collector_id: str, secret: str, legacy_secret: str = '') -> bool:
        valid_id = isinstance(collector_id, str) and bool(_ID.fullmatch(collector_id))
        valid_secret = isinstance(secret, str) and 1 <= len(secret) <= 256 and secret.isascii()
        candidate = hashlib.sha256(secret.encode('ascii')).digest() if valid_secret else _DUMMY
        with self.history._connection() as conn:
            self._table(conn)
            row = conn.execute('SELECT secret_hash FROM collector_credentials WHERE collector_id=?',
                               (collector_id if valid_id else '',)).fetchone()
            if row is not None:
                status = self._status(row[0])
                expected = row[0] if status == 'active' else _DUMMY
                return bool(valid_id and valid_secret and status == 'active' and hmac.compare_digest(expected, candidate))
        # Legacy credentials are accepted only for IDs with no registration
        # record; a revoked collector retains its tombstone permanently.
        return bool(valid_id and valid_secret and legacy_secret and
                    hmac.compare_digest(secret.encode('utf-8'), legacy_secret.encode('utf-8')))

    def _transition(self, collector_id: str, reissue: bool) -> str | None:
        if not isinstance(collector_id, str) or not _ID.fullmatch(collector_id):
            raise ValueError('Invalid collector identifier')
        secret = secrets.token_urlsafe(32) if reissue else None
        digest = hashlib.sha256(secret.encode('ascii')).digest() if secret else b''
        with self.history._connection() as conn:
            self._table(conn)
            conn.execute('BEGIN IMMEDIATE')
            row = conn.execute('SELECT secret_hash FROM collector_credentials WHERE collector_id=?', (collector_id,)).fetchone()
            if row is None:
                outcome = 'missing'
            elif self._status(row[0]) != ('revoked' if reissue else 'active'):
                outcome = 'conflict'
            else:
                conn.execute('UPDATE collector_credentials SET secret_hash=? WHERE collector_id=?', (digest, collector_id))
                conn.execute('INSERT INTO collector_credential_changes VALUES (?,?) '
                             'ON CONFLICT(collector_id) DO UPDATE SET changed_at=excluded.changed_at',
                             (collector_id, datetime.now(timezone.utc).isoformat()))
                outcome = 'ok'
            conn.execute('COMMIT')
        if outcome == 'missing':
            raise CollectorNotFound('Collector not found')
        if outcome == 'conflict':
            raise CollectorStateConflict('Collector credential state conflict')
        return secret

    def revoke(self, collector_id: str) -> None:
        self._transition(collector_id, False)

    def reissue(self, collector_id: str) -> str:
        return self._transition(collector_id, True)

    def list_collectors(self) -> list[dict]:
        with self.history._connection() as conn:
            self._table(conn)
            rows = conn.execute('SELECT r.collector_id, c.last_received_at, c.last_heartbeat_at, '
                                'c.reported_state, c.last_error_at, c.last_error_code, r.secret_hash, m.changed_at '
                                'FROM collector_credentials r LEFT JOIN collectors c '
                                'ON r.collector_id=c.collector_id LEFT JOIN collector_credential_changes m '
                                'ON m.collector_id=r.collector_id ORDER BY r.collector_id').fetchall()
            names = ('collector_id', 'last_received_at', 'last_heartbeat_at', 'reported_state',
                     'last_error_at', 'last_error_code')
            return [{**dict(zip(names, row[:6])), 'credential_state': self._status(row[6]),
                     'credential_changed_at': row[7]} for row in rows]
