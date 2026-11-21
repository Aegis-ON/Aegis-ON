import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from aegis_on import api
from aegis_on.service import DetectionService


class DemoScenariosTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict('os.environ', {'AEGIS_API_TOKEN': 'test-secret', 'AEGIS_ANALYST_NAME': 'analyst-1'})
        self.env.start()
        api.service = DetectionService()
        self.client = TestClient(api.app, base_url='https://testserver')
        self.headers = {'Authorization': 'Bearer test-secret'}

    def tearDown(self):
        self.client.close()
        self.env.stop()

    def analyze_scenario(self, name):
        response = self.client.get(f'/api/v1/demo/scenarios/{name}', headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.headers['content-type'].startswith('application/json'))
        data = response.json()
        self.assertIsInstance(data['events'], list)
        result = self.client.post('/api/v1/sysmon/analyze', json=data, headers=self.headers)
        self.assertEqual(result.status_code, 200, result.text)
        return data, result.json()

    def test_scenario_a_normal_process_has_no_findings(self):
        sample, result = self.analyze_scenario('a')
        self.assertEqual(len(sample['events']), 1)
        self.assertEqual(result['summary']['processed'], 1)
        self.assertEqual(result['detections'], [])
        self.assertEqual(result['source_events'][0]['sysmon_event_id'], 1)

    def test_scenario_b_download_rule_and_simulated_approval(self):
        sample, result = self.analyze_scenario('b')
        self.assertEqual(result['summary']['processed'], 1)
        source = result['source_events'][0]
        rule = next(d for d in result['detections'] if d['technique'] == 'T1105' and d['source'] == 'rule')
        self.assertIn(source['event_id'], rule['event_ids'])
        response = self.client.post('/api/v1/detections/' + rule['detection_id'] + '/approval',
                                    headers=self.headers, json={'analyst': 'analyst-1', 'rationale': 'demo'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['simulation_only'])
        self.assertEqual(response.json()['detection']['status'], 'approved_for_simulated_response')

    def test_scenario_c_distinct_outbound_fanout(self):
        sample, result = self.analyze_scenario('c')
        self.assertEqual(result['summary']['processed'], 3)
        self.assertTrue(all(e['EventData']['Initiated'] == 'true' for e in sample['events']))
        self.assertEqual(len({e['EventData']['DestinationIp'] for e in sample['events']}), 3)
        self.assertTrue(all(e['initiated'] is True for e in result['source_events']))
        correlation = [d for d in result['detections'] if d['source'] == 'correlation']
        self.assertEqual(len(correlation), 1)
        self.assertEqual(set(correlation[0]['event_ids']), {e['event_id'] for e in result['source_events']})
        self.assertIn('3 unique destinations in ten minutes', correlation[0]['evidence'])

    def test_authentication_and_allowlist(self):
        for name in ('a', 'b', 'c'):
            self.assertEqual(self.client.get(f'/api/v1/demo/scenarios/{name}').status_code, 401)
            self.assertEqual(self.client.get(f'/api/v1/demo/scenarios/{name}', headers={'Authorization':'Bearer wrong'}).status_code, 401)
        for name in ('unknown', 'A', 'scenario_a.json', '..%2F..%2FREADME.md', '%2e%2e%2fdata%2fdemo_sysmon.json'):
            self.assertEqual(self.client.get(f'/api/v1/demo/scenarios/{name}', headers=self.headers).status_code, 404)


if __name__ == '__main__':
    unittest.main()
