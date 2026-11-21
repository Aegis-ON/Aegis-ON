"""Portable collector contracts; does not replace actual PowerShell/Windows tests."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import unittest


ROOT = Path(__file__).resolve().parent.parent


class CollectorTests(unittest.TestCase):
    def test_synthetic_collector_retries_same_batch_until_ack(self):
        requests = []
        collector_headers = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers['Content-Length']))
                requests.append((self.path, self.headers.get('Idempotency-Key'), body))
                collector_headers.append(self.headers.get('X-Collector-ID'))
                submissions = [x for x in requests if x[0] == '/api/v1/ingest/sysmon']
                if self.path == '/api/v1/ingest/sysmon' and len(submissions) == 1:
                    self.send_response(503)
                    payload = {}
                else:
                    self.send_response(200)
                    payload = {'analysis_id': 'synthetic', 'summary': {'processed': 1}}
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(payload).encode())
            def log_message(self, *_args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            result = subprocess.run([sys.executable, str(ROOT / 'scripts' / 'collect_synthetic.py'),
                                     '--port', str(server.server_port), '--interval', '0',
                                     '--retry-delay', '0', '--retries', '1'],
                                    env={**os.environ, 'AEGIS_API_TOKEN': 'synthetic-test-token'},
                                    capture_output=True, text=True, timeout=15)
        finally:
            server.shutdown(); server.server_close(); worker.join(timeout=2)
        self.assertEqual(result.returncode, 0, result.stderr)
        submitted = [x for x in requests if x[0] == '/api/v1/ingest/sysmon']
        self.assertEqual(len(submitted), 6)
        self.assertEqual(submitted[0][1:], submitted[1][1:])
        self.assertIn('not acknowledged; retrying', result.stderr)
        self.assertNotIn('synthetic-test-token', result.stdout + result.stderr)
        self.assertNotIn('curl https://example.org', result.stdout + result.stderr)
        heartbeat = [json.loads(x[2]) for x in requests if x[0].endswith('/heartbeat')]
        self.assertEqual([x['state'] for x in heartbeat], ['running', 'error', 'running', 'stopped'])
        self.assertTrue(collector_headers)
        self.assertEqual(set(collector_headers), {'synthetic-collector'})

    def test_synthetic_collector_reuses_key_when_ack_is_lost(self):
        submissions = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers['Content-Length']))
                if self.path == '/api/v1/ingest/sysmon':
                    submissions.append((self.headers.get('Idempotency-Key'), body))
                    if len(submissions) == 1:
                        # Simulate commit followed by connection loss before ACK.
                        self.close_connection = True
                        self.connection.shutdown(socket.SHUT_RDWR)
                        self.connection.close()
                        return
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"analysis_id":"synthetic","summary":{"processed":1}}')
            def log_message(self, *_args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            result = subprocess.run([sys.executable, str(ROOT / 'scripts' / 'collect_synthetic.py'),
                                     '--port', str(server.server_port), '--interval', '0',
                                     '--retry-delay', '0', '--retries', '1'],
                                    env={**os.environ, 'AEGIS_API_TOKEN': 'synthetic-test-token'},
                                    capture_output=True, text=True, timeout=15)
        finally:
            server.shutdown(); server.server_close(); worker.join(timeout=2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(submissions), 6)
        self.assertEqual(submissions[0], submissions[1])

    def test_windows_script_documents_transport_and_checkpoint_guards(self):
        # Only structural checks: syntax and execution still require PowerShell/Windows.
        script = (ROOT / 'scripts' / 'collect_sysmon.ps1').read_text(encoding='utf-8')
        self.assertIn("$server.Scheme -ne 'https'", script)
        self.assertIn('$server.IsLoopback', script)
        self.assertIn("'X-Collector-ID' = $CollectorId", script)
        self.assertEqual(script.count('-MaximumRedirection 0'), 2)
        self.assertIn('$cursor.binding', script)
        self.assertIn('$AdoptExistingCursor', script)
        self.assertIn('if (-not $response.analysis_id)', script)
        self.assertLess(script.index('if (-not $response.analysis_id)'), script.index('Write-Cursor $end'))


if __name__ == '__main__':
    unittest.main()
