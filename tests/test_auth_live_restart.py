"""Real loopback server restart with synthetic credentials and isolated SQLite."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


def test_cross_batch_auth_survives_real_server_restart():
    with tempfile.TemporaryDirectory() as temp:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        env = {**os.environ, 'PYTHONPATH': 'src', 'AEGIS_HISTORY_DB': str(Path(temp) / 'history.sqlite3'),
               'AEGIS_API_TOKEN': 'fictional-token', 'AEGIS_ANALYST_NAME': 'analyst',
               'AEGIS_ALLOW_LEGACY_COLLECTOR_TOKEN': '1', 'AEGIS_ATTACK_MODEL_DIR': '', 'AEGIS_PII_MODEL_DIR': '',
               'AEGIS_LOGIN_USERNAME': '', 'AEGIS_LOGIN_PASSWORD_HASH': ''}
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def request(method, path, body=None, batch=None):
            headers = {'Authorization': 'Bearer fictional-token', 'X-Collector-ID': 'demo', 'Content-Type': 'application/json'}
            if batch:
                headers['Idempotency-Key'] = batch
            data = json.dumps(body).encode() if body is not None else None
            req = urllib.request.Request(f'http://127.0.0.1:{port}' + path, method=method, data=data, headers=headers)
            with opener.open(req, timeout=3) as response:
                return json.load(response)

        def start():
            server = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'aegis_on.api:app', '--host', '127.0.0.1',
                                       '--port', str(port), '--log-level', 'error'], env=env,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(100):
                if server.poll() is not None:
                    raise AssertionError('server exited during startup')
                try:
                    request('GET', '/api/v1/health')
                    return server
                except (OSError, urllib.error.URLError):
                    time.sleep(0.05)
            server.terminate()
            server.wait(timeout=5)
            raise AssertionError('server did not become ready')

        def event(i):
            return {'event_id': f'id-{i}', 'timestamp': f'2026-01-01T00:0{i}:00Z', 'host': 'fixture-host',
                    'account': 'fixture-account', 'source_ip': '192.0.2.7', 'outcome': 'success' if i == 3 else 'failure'}

        server = start()
        try:
            for i in range(3):
                result = request('POST', '/api/v1/ingest/auth', {'events': [event(i)]}, f'batch-{i}')
                assert result['summary']['processed'] == 1
        finally:
            server.terminate()
            server.wait(timeout=10)
        server = start()
        try:
            result = request('POST', '/api/v1/ingest/auth', {'events': [event(0), event(3)]}, 'mixed-after-restart')
            assert result['summary']['processed'] == 1 and result['summary']['duplicate'] == 1
            history = request('GET', '/api/v1/history')
            assert len(history['detections']) == 1
            assert len(history['detections'][0]['event_ids']) == 4
        finally:
            server.terminate()
            server.wait(timeout=10)
        raw = (Path(temp) / 'history.sqlite3').read_bytes()
        for value in (b'fictional-token', b'fixture-account', b'192.0.2.7'):
            assert value not in raw
