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
        self.client = TestClient(api.app); self.addCleanup(self.client.close)

    def test_shells_resolve_on_direct_load_and_data_remains_authenticated(self):
        landing = self.client.get('/')
        self.assertEqual(landing.status_code, 200)
        self.assertIn('이벤트를 읽고', landing.text)
        for path in ['/console','/console/endpoints','/console/endpoints/'+'a'*64,'/console/detections','/console/history']:
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertIn('관제 메뉴', response.text)
        self.assertIn('JSON 이벤트 직접 입력', self.client.get('/console/analysis').text)
        self.assertEqual(self.client.get('/console/no-such-page').status_code, 404)
        self.assertEqual(self.client.get('/api/v1/history').status_code, 401)
        self.assertEqual(self.client.get('/api/v1/endpoints').status_code, 401)
        self.assertEqual(self.client.get('/api/v1/endpoints/'+'a'*64).status_code, 401)

    def test_legacy_hash_targets_remain_redirectable(self):
        html = self.client.get('/').text
        for fragment in ['#analysis','#result-section','#history','#overview']:
            self.assertIn(fragment, html)
        self.assertIn("'/console/history'", html)

if __name__ == '__main__': unittest.main()
