"""Explicit per-collector credentials, independent of observed heartbeats.

Secrets are high-entropy machine credentials, not passwords; only their SHA-256
digests are retained. Existing observation rows do not grant access.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets

from .history_store import SQLiteHistory

_ID = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
_DUMMY = hashlib.sha256(b'aegis-collector-dummy').digest()


class CollectorExists(ValueError):
    """Collector identifier was already registered."""


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
                conn.execute('COMMIT')
        if exists:
            raise CollectorExists('Collector already registered')
        return secret

    def authenticate(self, collector_id: str, secret: str) -> bool:
        valid_id = isinstance(collector_id, str) and bool(_ID.fullmatch(collector_id))
        valid_secret = isinstance(secret, str) and 1 <= len(secret) <= 256 and secret.isascii()
        candidate = hashlib.sha256(secret.encode('ascii')).digest() if valid_secret else _DUMMY
        with self.history._connection() as conn:
            self._table(conn)
            row = conn.execute('SELECT secret_hash FROM collector_credentials WHERE collector_id=?',
                               (collector_id if valid_id else '',)).fetchone()
        expected = bytes(row[0]) if row and isinstance(row[0], bytes) else _DUMMY
        matched = hmac.compare_digest(expected, candidate)
        return bool(valid_id and valid_secret and row and matched)

    def list_collectors(self) -> list[dict]:
        with self.history._connection() as conn:
            self._table(conn)
            rows = conn.execute('SELECT r.collector_id, c.last_received_at, c.last_heartbeat_at, '
                                'c.reported_state, c.last_error_at, c.last_error_code '
                                'FROM collector_credentials r LEFT JOIN collectors c '
                                'ON r.collector_id=c.collector_id ORDER BY r.collector_id').fetchall()
        names = ('collector_id', 'last_received_at', 'last_heartbeat_at', 'reported_state',
                 'last_error_at', 'last_error_code')
        return [dict(zip(names, row)) for row in rows]
