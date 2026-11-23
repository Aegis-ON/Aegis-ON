"""Public shells contain no data; authenticated APIs back console views."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from aegis_on import api
from aegis_on.history_store import SQLiteHistory
from aegis_on.service import DetectionService

class ConsoleRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        old = api.service; self.addCleanup(setattr, api, 'service', old)
        api.service = DetectionService(SQLiteHistory(Path(self.tmp.name) / 'history.sqlite3'))
        self.env = patch.dict('os.environ', {'AEGIS_API_TOKEN':'route-test-token','AEGIS_ANALYST_NAME':'test-analyst'})
        self.env.start(); self.addCleanup(self.env.stop)
        self.client = TestClient(api.app, base_url='https://testserver'); self.addCleanup(self.client.close)

    def test_shells_resolve_on_direct_load_and_data_remains_authenticated(self):
        landing = self.client.get('/')
        self.assertEqual(landing.status_code, 200)
        self.assertIn('/assets/aegis/app.js', landing.text)
        self.assertNotIn('제품 소개', landing.text)
        for path in ['/console','/console/endpoints','/console/endpoints/'+'a'*64,'/console/detections','/console/events','/console/history']:
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertIn('/assets/aegis/app.js', response.text)
        replay = self.client.get('/console/replay')
        self.assertEqual(replay.status_code, 200)
        self.assertIn('LOCAL REPLAY · STATIC SNAPSHOT', replay.text)
        self.assertIn('/api/v1/replay/summary', replay.text)
        self.assertNotIn('JSON 이벤트 직접 입력', self.client.get('/console/analysis').text)
        self.assertIn('/assets/aegis/app.js', self.client.get('/console/events').text)
        self.assertEqual(self.client.get('/console/no-such-page').status_code, 404)
        self.assertEqual(self.client.get('/api/v1/history').status_code, 401)
        self.assertEqual(self.client.get('/api/v1/endpoints').status_code, 401)
        self.assertEqual(self.client.get('/api/v1/endpoints/'+'a'*64).status_code, 401)

    def test_replay_summary_is_authenticated_and_read_only(self):
        self.assertEqual(self.client.get('/api/v1/replay/summary').status_code, 401)
        response = self.client.get('/api/v1/replay/summary', headers={'Authorization': 'Bearer route-test-token'})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['replay_mode'])
        self.assertFalse(data['live_collection'])
        self.assertFalse(data['external_rule_execution'])
        self.assertEqual(data['summary']['case_count'], 10)
        self.assertEqual(data['summary']['supervised_evaluation_status'], 'insufficient_for_supervised_model_evaluation')
        simulated = [row for row in data['alerts'] if row['simulated']]
        self.assertEqual(len(simulated), 1)
        self.assertEqual(simulated[0]['display_label'], 'simulated_confirmed_security_incident')
        hexstrike = next(row for row in data['alerts'] if row['hexstrike_blocked'])
        self.assertEqual(hexstrike['classification'], 'policy_blocked')

    def test_only_bundled_assets_are_served(self):
        for asset, content_type in [('app.js', 'javascript'), ('app.css', 'text/css')]:
            response = self.client.get('/assets/aegis/' + asset)
            self.assertEqual(response.status_code, 200)
            self.assertIn(content_type, response.headers['content-type'])
        self.assertEqual(self.client.get('/assets/aegis/index.html').status_code, 404)

    def test_legacy_hash_targets_remain_redirectable(self):
        html = self.client.get('/assets/aegis/app.js').text
        for fragment in ['#analysis','#result-section','#history','#overview']:
            self.assertIn(fragment, html)
        self.assertIn("/console/history", html)

if __name__ == '__main__': unittest.main()
