"""Registered machine credentials are bound to one collection identity."""
import os
from pathlib import Path
import tempfile
import threading
import unittest

from aegis_on.collector_auth import CollectorExists, CollectorRegistry
from aegis_on.history_store import SQLiteHistory


class CollectorCredentialTests(unittest.TestCase):
    def test_registered_credentials_survive_restart_and_are_bound_to_id(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'history.sqlite3'
            registry = CollectorRegistry(SQLiteHistory(path))
            first = registry.register('pc_one')
            second = registry.register('pc_two')
            self.assertNotEqual(first, second)
            reopened = CollectorRegistry(SQLiteHistory(path))
            self.assertTrue(reopened.authenticate('pc_one', first))
            self.assertTrue(reopened.authenticate('pc_two', second))
            self.assertFalse(reopened.authenticate('pc_two', first))
            self.assertFalse(reopened.authenticate('unknown', first))
            self.assertFalse(reopened.authenticate('pc_one', ''))
            self.assertEqual([item['collector_id'] for item in reopened.list_collectors()], ['pc_one', 'pc_two'])
            self.assertIsNone(reopened.list_collectors()[0]['last_heartbeat_at'])
            with self.assertRaises(CollectorExists):
                reopened.register('pc_one')
            self.assertTrue(reopened.authenticate('pc_one', first))
            self.assertNotIn(first.encode(), path.read_bytes())
            self.assertNotIn(second.encode(), path.read_bytes())
            if os.name == 'posix':
                self.assertEqual(path.stat().st_mode & 0o077, 0)

    def test_observed_collector_is_not_automatically_registered(self):
        with tempfile.TemporaryDirectory() as directory:
            history = SQLiteHistory(Path(directory) / 'history.sqlite3')
            history.heartbeat('legacy', 'running', None)
            registry = CollectorRegistry(history)
            self.assertEqual(registry.list_collectors(), [])
            self.assertFalse(registry.authenticate('legacy', 'any-value'))
            with self.assertRaises(CollectorExists):
                registry.register('legacy')

    def test_invalid_ids_and_tokens_fail_safely(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = CollectorRegistry(SQLiteHistory(Path(directory) / 'history.sqlite3'))
            for invalid in ('', '../host', 'x' * 65, '한글'):
                with self.subTest(invalid=invalid):
                    with self.assertRaises(ValueError):
                        registry.register(invalid)
                    self.assertFalse(registry.authenticate(invalid, 'secret'))
            secret = registry.register('valid')
            self.assertFalse(registry.authenticate('valid', '한글'))
            self.assertFalse(registry.authenticate('valid', 'x' * 1000))
            self.assertTrue(registry.authenticate('valid', secret))

    def test_racing_registration_issues_only_one_credential(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'history.sqlite3'
            CollectorRegistry(SQLiteHistory(path)).list_collectors()
            barrier = threading.Barrier(2)
            issued, errors = [], []
            def register():
                registry = CollectorRegistry(SQLiteHistory(path))
                barrier.wait()
                try:
                    issued.append(registry.register('pc'))
                except CollectorExists:
                    errors.append('conflict')
            threads = [threading.Thread(target=register) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(len(issued), 1)
            self.assertEqual(errors, ['conflict'])
            self.assertTrue(CollectorRegistry(SQLiteHistory(path)).authenticate('pc', issued[0]))


if __name__ == '__main__':
    unittest.main()
