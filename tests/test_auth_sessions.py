import os
from pathlib import Path
import sqlite3
from contextlib import closing
import tempfile
import unittest
from unittest.mock import patch

from aegis_on.auth_sessions import AuthConfigurationError, AuthSessions, AuthStorageError, hash_password, verify_password


class SessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = 'sample-password-not-real'
        cls.password_hash = hash_password(cls.password)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / 'sessions.sqlite3')
        self.now = 1000.0
        self.auth = AuthSessions(self.path, 'analyst', self.password_hash, 'Analyst', ttl_seconds=60, clock=lambda: self.now)

    def test_password_hash_and_invalid_credentials(self):
        self.assertNotEqual(self.password_hash, hash_password(self.password))
        self.assertTrue(verify_password(self.password, self.password_hash))
        self.assertFalse(verify_password('wrong-password', self.password_hash))
        self.assertIsNone(self.auth.login('analyst', 'wrong-password'))
        self.assertIsNone(self.auth.login('wrong', self.password))
        self.assertIsNone(self.auth.login('analyst', '\ud800'))
        self.assertIsNone(self.auth.login('\ud800', self.password))
        with self.assertRaises(ValueError):
            hash_password('short')
        with self.assertRaises(AuthConfigurationError):
            verify_password(self.password, 'scrypt$1048576$8$1$00$00')

    def test_persistent_session_expiry_logout_and_csrf(self):
        ticket = self.auth.login('analyst', self.password)
        self.assertIsNotNone(ticket)
        self.assertNotIn(ticket.session_token, repr(ticket))
        self.assertEqual(self.auth.authenticate(ticket.session_token), 'Analyst')
        self.assertTrue(self.auth.verify_csrf(ticket.session_token, ticket.csrf_token))
        self.assertFalse(self.auth.verify_csrf(ticket.session_token, 'bad'))
        self.assertFalse(self.auth.verify_csrf(ticket.session_token, '💩' * 64))
        restarted = AuthSessions(self.path, 'analyst', self.password_hash, 'Analyst', ttl_seconds=60, clock=lambda: self.now)
        self.assertEqual(restarted.authenticate(ticket.session_token), 'Analyst')
        restarted.logout(ticket.session_token)
        self.assertIsNone(self.auth.authenticate(ticket.session_token))
        self.assertFalse(self.auth.verify_csrf(ticket.session_token, ticket.csrf_token))
        ticket = self.auth.login('analyst', self.password)
        self.now = ticket.expires_at
        self.assertIsNone(self.auth.authenticate(ticket.session_token))

    def test_no_plaintext_or_session_token_in_db(self):
        ticket = self.auth.login('analyst', self.password)
        raw = Path(self.path).read_bytes()
        self.assertNotIn(ticket.session_token.encode(), raw)
        self.assertNotIn(self.password.encode(), raw)
        with closing(sqlite3.connect(self.path)) as conn, conn:
            self.assertNotEqual(conn.execute('SELECT token_hash FROM sessions').fetchone()[0], ticket.session_token)
        if os.name == 'posix':
            self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_credential_changes_invalidate_existing_sessions(self):
        ticket = self.auth.login('analyst', self.password)
        changed = AuthSessions(self.path, 'analyst', hash_password('another-password-value'), 'Analyst')
        self.assertIsNone(changed.authenticate(ticket.session_token))
        renamed = AuthSessions(self.path, 'analyst', self.password_hash, 'Different analyst')
        self.assertIsNone(renamed.authenticate(ticket.session_token))

    def test_corruption_replacement_and_version_fail_closed(self):
        ticket = self.auth.login('analyst', self.password)
        Path(self.path).unlink()
        with self.assertRaises(AuthStorageError):
            self.auth.authenticate(ticket.session_token)
        Path(self.path).write_bytes(b'')
        os.chmod(self.path, 0o600)
        with self.assertRaises(AuthStorageError):
            AuthSessions(self.path, 'analyst', self.password_hash, 'Analyst')
        Path(self.path).unlink()
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute('PRAGMA user_version = 999')
        os.chmod(self.path, 0o600)
        with self.assertRaises(AuthStorageError):
            AuthSessions(self.path, 'analyst', self.password_hash, 'Analyst')

    def test_unsafe_existing_path_fails_closed(self):
        if os.name != 'posix':
            self.skipTest('POSIX permissions required')
        os.chmod(self.path, 0o644)
        with self.assertRaises(AuthStorageError):
            self.auth.login('analyst', self.password)
        os.chmod(self.path, 0o600)
        link = str(Path(self.tmp.name) / 'link')
        os.symlink(self.path, link)
        with self.assertRaises(AuthStorageError):
            AuthSessions(link, 'analyst', self.password_hash, 'Analyst')

    def test_environment_config_and_ttl(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(AuthSessions.from_environment())
        with patch.dict(os.environ, {'AEGIS_LOGIN_USERNAME': 'analyst'}, clear=True):
            with self.assertRaises(AuthConfigurationError):
                AuthSessions.from_environment()
        with patch.dict(os.environ, {'AEGIS_LOGIN_USERNAME': 'analyst', 'AEGIS_LOGIN_PASSWORD_HASH': self.password_hash,
                                    'AEGIS_ANALYST_NAME': 'Analyst', 'AEGIS_AUTH_DB': self.path,
                                    'AEGIS_SESSION_TTL_SECONDS': '59'}, clear=True):
            with self.assertRaises(AuthConfigurationError):
                AuthSessions.from_environment()


if __name__ == '__main__':
    unittest.main()
