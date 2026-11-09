import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from fastapi.testclient import TestClient
from aegis_on import api
from aegis_on.service import DetectionService


class ApprovalIdempotencyTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict('os.environ', {'AEGIS_API_TOKEN': 'test-secret', 'AEGIS_ANALYST_NAME': 'analyst-1'})
        self.env.start()
        api.service = DetectionService()
        self.client = TestClient(api.app)
        self.headers = {'Authorization': 'Bearer test-secret'}
        sample = self.client.get('/api/v1/demo/scenarios/b', headers=self.headers).json()
        analysis = self.client.post('/api/v1/sysmon/analyze', headers=self.headers, json=sample)
        self.assertEqual(analysis.status_code, 200)
        self.detection_id = analysis.json()['detections'][0]['detection_id']
        self.url = '/api/v1/detections/' + self.detection_id + '/approval'

    def tearDown(self):
        self.client.close()
        self.env.stop()

    def post(self, reason='first reason', headers=None):
        return self.client.post(self.url, headers=self.headers if headers is None else headers,
                                json={'analyst': 'analyst-1', 'rationale': reason})

    def test_sequential_retry_keeps_first_evidence_and_result(self):
        first = self.post()
        second = self.post('different later reason')
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertTrue(first.json()['simulation_only'])
        self.assertEqual(first.json(), second.json())
        evidence = second.json()['detection']['evidence']
        self.assertEqual(sum(item.startswith('approved locally by ') for item in evidence), 1)
        self.assertEqual([item for item in evidence if item.startswith('analyst rationale:')],
                         ['analyst rationale: first reason'])

    def test_concurrent_http_retries_record_approval_once(self):
        count = 12
        barrier = threading.Barrier(count)
        def approve(index):
            barrier.wait(timeout=10)
            response = self.post(f'concurrent reason {index}')
            return response.status_code, response.json()
        with ThreadPoolExecutor(max_workers=count) as executor:
            responses = list(executor.map(approve, range(count)))
        self.assertTrue(all(status == 200 for status, _ in responses))
        first = responses[0][1]
        self.assertTrue(all(payload == first for _, payload in responses))
        evidence = first['detection']['evidence']
        self.assertEqual(sum(item.startswith('approved locally by ') for item in evidence), 1)
        reasons = [item for item in evidence if item.startswith('analyst rationale:')]
        self.assertEqual(len(reasons), 1)
        self.assertIn(reasons[0], [f'analyst rationale: concurrent reason {i}' for i in range(count)])

    def test_empty_initial_reason_is_not_overwritten_by_retry(self):
        first = self.post('')
        later = self.post('later reason')
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json(), later.json())
        self.assertFalse(any(item.startswith('analyst rationale:') for item in later.json()['detection']['evidence']))

    def test_authentication_validation_and_missing_detection_are_preserved(self):
        self.assertEqual(self.post(headers={}).status_code, 401)
        bad_analyst = self.client.post(self.url, headers=self.headers, json={'analyst': 'other'})
        self.assertEqual(bad_analyst.status_code, 403)
        self.assertEqual(self.client.post('/api/v1/detections/nonexistent/approval',
                         headers=self.headers, json={'analyst': 'analyst-1'}).status_code, 404)
        self.assertEqual(self.post().status_code, 200)
        payload = json.dumps({'analyst': 'analyst-1', 'rationale': '\ud800'}, ensure_ascii=True).encode()
        response = self.client.post(self.url, content=payload,
                                    headers={**self.headers, 'Content-Type': 'application/json'})
        self.assertEqual(response.status_code, 422)


if __name__ == '__main__':
    unittest.main()
