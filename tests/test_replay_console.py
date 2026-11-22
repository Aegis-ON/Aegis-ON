import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ReplayConsoleFixtureTests(unittest.TestCase):
    def test_fixture_is_pseudonymized_read_only_replay(self):
        fixture = json.loads((ROOT / 'data' / 'replay_soc_fixture.json').read_text(encoding='utf-8'))
        self.assertTrue(fixture['replay_mode'])
        self.assertFalse(fixture['live_collection'])
        self.assertFalse(fixture['external_rule_execution'])
        self.assertEqual(fixture['summary']['case_count'], len(fixture['alerts']))
        self.assertEqual(fixture['summary']['event_count'], 102)
        self.assertEqual(fixture['summary']['supervised_evaluation_status'], 'insufficient_for_supervised_model_evaluation')
        self.assertEqual(sum(row['simulated'] for row in fixture['alerts']), 1)
        self.assertTrue(all('confirmed_security_incident' not in row['classification'] or row['simulated'] for row in fixture['alerts']))
        self.assertTrue(any(row['hexstrike_blocked'] and row['classification'] == 'policy_blocked' for row in fixture['alerts']))

    def test_page_declares_static_boundaries_and_uses_authenticated_summary(self):
        page = (ROOT / 'static' / 'replay.html').read_text(encoding='utf-8')
        for required in ('LOCAL REPLAY · STATIC SNAPSHOT', '/api/v1/replay/summary', 'SIMULATED', 'BLOCKED — NOT RUN', '실시간 수집·차단 없음'):
            self.assertIn(required, page)
        self.assertNotIn('http://', page)
        self.assertNotIn('https://', page)


if __name__ == '__main__':
    unittest.main()
