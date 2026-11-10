"""Single configured analyst credentials and revocable, persistent sessions.

This module never accepts or stores plaintext passwords in configuration. The
caller must enforce CSRF protection and set appropriate cookie attributes.
"""
from __future__ import annotations

import getpass
from contextlib import closing
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import sys
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import quote


class AuthConfigurationError(Exception):
    """Login configuration is missing or invalid."""


class AuthStorageError(Exception):
    """The session store cannot be safely used."""


_TOKEN = re.compile(r'^[A-Za-z0-9_-]{43}$')
_N, _R, _P = 16384, 8, 5


def hash_password(password: str) -> str:
    """Generate a salted scrypt verifier; do not retain the input password."""
    try:
        encoded_password = password.encode('utf-8') if isinstance(password, str) else b''
    except UnicodeError:
        encoded_password = b''
    if not isinstance(password, str) or len(password) < 12 or not encoded_password or len(encoded_password) > 1024:
        raise ValueError('Password must contain at least 12 characters and at most 1024 UTF-8 bytes')
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(encoded_password, salt=salt, n=_N, r=_R, p=_P, dklen=32, maxmem=64 * 1024 * 1024)
    return f'scrypt${_N}${_R}${_P}${salt.hex()}${digest.hex()}'


def _parse_hash(encoded: str) -> tuple[bytes, bytes]:
    try:
        algo, n, r, p, salt, digest = encoded.split('$')
        if (algo, n, r, p) != ('scrypt', str(_N), str(_R), str(_P)):
            raise ValueError
        s, d = bytes.fromhex(salt), bytes.fromhex(digest)
        if len(s) != 16 or len(d) != 32 or salt != s.hex() or digest != d.hex():
            raise ValueError
        return s, d
    except (AttributeError, TypeError, ValueError):
        raise AuthConfigurationError('Invalid password verifier') from None


def verify_password(password: str, encoded: str) -> bool:
    salt, expected = _parse_hash(encoded)
    try:
        encoded_password = password.encode('utf-8') if isinstance(password, str) else b''
    except UnicodeError:
        return False
    if not isinstance(password, str) or len(encoded_password) > 1024:
        return False
    actual = hashlib.scrypt(encoded_password, salt=salt, n=_N, r=_R, p=_P, dklen=32, maxmem=64 * 1024 * 1024)
    return hmac.compare_digest(actual, expected)


@dataclass(frozen=True, repr=False)
class SessionTicket:
    session_token: str
    csrf_token: str
    expires_at: float


class AuthSessions:
    """One analyst account; tokens are random and only their digests are stored."""

    def __init__(self, db_path: str | os.PathLike[str], username: str, password_hash: str,
                 analyst: str, *, ttl_seconds: int = 3600, clock: Callable[[], float] = time.time):
        if not isinstance(username, str) or not username.strip() or len(username) > 128:
            raise AuthConfigurationError('Invalid username')
        if not isinstance(analyst, str) or not analyst.strip() or len(analyst) > 128:
            raise AuthConfigurationError('Invalid analyst identity')
        if not isinstance(ttl_seconds, int) or not 60 <= ttl_seconds <= 86400:
            raise AuthConfigurationError('Session TTL must be 60 to 86400 seconds')
        _parse_hash(password_hash)
        self.path = os.fspath(db_path)
        if not self.path or self.path == ':memory:':
            raise AuthConfigurationError('Invalid session storage path')
        self.username, self.password_hash, self.analyst = username, password_hash, analyst
        self.ttl_seconds, self.clock = ttl_seconds, clock
        self.binding = hashlib.sha256((username + '\0' + password_hash + '\0' + analyst).encode('utf-8')).hexdigest()
        self._identity = None
        self._initialize()

    @classmethod
    def from_environment(cls) -> 'AuthSessions | None':
        username = os.getenv('AEGIS_LOGIN_USERNAME', '').strip()
        password_hash = os.getenv('AEGIS_LOGIN_PASSWORD_HASH', '').strip()
        if not username and not password_hash:
            return None
        analyst = os.getenv('AEGIS_ANALYST_NAME', '').strip()
        if not username or not password_hash or not analyst:
            raise AuthConfigurationError('Analyst login configuration is incomplete')
        try:
            ttl = int(os.getenv('AEGIS_SESSION_TTL_SECONDS', '3600'))
        except ValueError:
            raise AuthConfigurationError('Invalid session TTL') from None
        history = os.getenv('AEGIS_HISTORY_DB', str(Path.home() / '.aegis-on' / 'history.sqlite3'))
        path = os.getenv('AEGIS_AUTH_DB', history + '.auth')
        return cls(path, username, password_hash, analyst, ttl_seconds=ttl)

    def _open(self) -> sqlite3.Connection:
        try:
            st = os.lstat(self.path)
            if not stat.S_ISREG(st.st_mode) or (os.name == 'posix' and st.st_mode & 0o077):
                raise AuthStorageError('Session storage unavailable')
            identity = (st.st_dev, st.st_ino)
            if self._identity is not None and self._identity != identity:
                raise AuthStorageError('Session storage unavailable')
            self._identity = identity
            uri = 'file:' + quote(os.path.abspath(self.path), safe='/') + '?mode=rw'
            conn = sqlite3.connect(uri, uri=True, timeout=5)
            current = os.lstat(self.path)
            if (current.st_dev, current.st_ino) != identity:
                conn.close()
                raise AuthStorageError('Session storage unavailable')
            if conn.execute('PRAGMA user_version').fetchone()[0] != 1:
                conn.close()
                raise AuthStorageError('Session storage unavailable')
            return conn
        except (OSError, sqlite3.Error):
            raise AuthStorageError('Session storage unavailable') from None

    def _initialize(self) -> None:
        try:
            Path(self.path).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                created = False
            else:
                os.close(fd)
                created = True
            if not created:
                with closing(self._open()) as conn:
                    cols = {r[1] for r in conn.execute('PRAGMA table_info(sessions)')}
                    if cols != {'token_hash', 'binding', 'expires_at'}:
                        raise AuthStorageError('Session storage unavailable')
                return
            st = os.lstat(self.path)
            self._identity = (st.st_dev, st.st_ino)
            with closing(sqlite3.connect(self.path, timeout=5)) as conn, conn:
                conn.execute('CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, binding TEXT NOT NULL, expires_at REAL NOT NULL)')
                conn.execute('PRAGMA user_version = 1')
        except (OSError, sqlite3.Error):
            raise AuthStorageError('Session storage unavailable') from None

    @staticmethod
    def _digest(token: str) -> str | None:
        if not isinstance(token, str) or not _TOKEN.fullmatch(token):
            return None
        return hashlib.sha256(token.encode('ascii')).hexdigest()

    @staticmethod
    def csrf_token(token: str) -> str:
        if AuthSessions._digest(token) is None:
            raise ValueError('Invalid session token')
        return hmac.new(token.encode('ascii'), b'aegis-on:csrf:v1', hashlib.sha256).hexdigest()

    def login(self, username: str, password: str) -> SessionTicket | None:
        # Always derive a password hash for valid-sized input regardless of username.
        password_ok = verify_password(password, self.password_hash)
        try:
            username_ok = isinstance(username, str) and hmac.compare_digest(username.encode('utf-8'), self.username.encode('utf-8'))
        except UnicodeError:
            username_ok = False
        if not password_ok or not username_ok:
            return None
        token = secrets.token_urlsafe(32)
        expires = self.clock() + self.ttl_seconds
        try:
            with closing(self._open()) as conn, conn:
                conn.execute('DELETE FROM sessions WHERE expires_at <= ?', (self.clock(),))
                conn.execute('INSERT INTO sessions VALUES (?, ?, ?)', (self._digest(token), self.binding, expires))
        except sqlite3.Error:
            raise AuthStorageError('Session storage unavailable') from None
        return SessionTicket(token, self.csrf_token(token), expires)

    def authenticate(self, token: str) -> str | None:
        digest = self._digest(token)
        if digest is None:
            return None
        try:
            with closing(self._open()) as conn, conn:
                row = conn.execute('SELECT binding, expires_at FROM sessions WHERE token_hash = ?', (digest,)).fetchone()
            if row and hmac.compare_digest(row[0], self.binding) and row[1] > self.clock():
                return self.analyst
            return None
        except sqlite3.Error:
            raise AuthStorageError('Session storage unavailable') from None

    def verify_csrf(self, token: str, header: str | None) -> bool:
        if not isinstance(header, str) or not re.fullmatch(r'[0-9a-f]{64}', header):
            return False
        if self.authenticate(token) is None:
            return False
        return hmac.compare_digest(self.csrf_token(token), header)

    def logout(self, token: str) -> None:
        digest = self._digest(token)
        if digest is None:
            return
        try:
            with closing(self._open()) as conn, conn:
                conn.execute('DELETE FROM sessions WHERE token_hash = ?', (digest,))
        except sqlite3.Error:
            raise AuthStorageError('Session storage unavailable') from None


def _main() -> None:
    if sys.argv[1:] != ['hash-password']:
        raise SystemExit('Usage: python -m aegis_on.auth_sessions hash-password')
    password = getpass.getpass('Password (minimum 12 characters): ')
    confirmation = getpass.getpass('Repeat password: ')
    if password != confirmation:
        raise SystemExit('Passwords do not match')
    try:
        print(hash_password(password))
    except ValueError as exc:
        raise SystemExit(str(exc)) from None


if __name__ == '__main__':
    _main()
