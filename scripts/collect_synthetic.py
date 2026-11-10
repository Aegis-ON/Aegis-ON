"""Send only the bundled fictional Sysmon fixture to a local Aegis-ON server.

This is a repeatable end-to-end test helper, not a Windows Sysmon collector.
It deliberately has no input path or remote URL option.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.request
import uuid

FIXTURE = Path(__file__).resolve().parent.parent / 'data' / 'demo_sysmon.json'


def post(port: int, path: str, body: object, token: str, headers: dict[str, str] | None = None) -> dict:
    data = json.dumps(body, separators=(',', ':'), ensure_ascii=True).encode('utf-8')
    request = urllib.request.Request(
        f'http://127.0.0.1:{port}{path}', data=data, method='POST',
        headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json', **(headers or {})},
    )
    # No redirects: never forward the bearer token to another host.
    opener = urllib.request.build_opener(_NoRedirect())
    with opener.open(request, timeout=15) as response:
        return json.load(response)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--interval', type=float, default=2.0)
    parser.add_argument('--collector-id', default='synthetic-collector')
    parser.add_argument('--retries', type=int, default=10)
    parser.add_argument('--retry-delay', type=float, default=2.0)
    args = parser.parse_args()
    if (not 1 <= args.port <= 65535 or not 0 <= args.interval <= 60
            or not 0 <= args.retries <= 100 or not 0 <= args.retry_delay <= 60
            or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', args.collector_id)):
        parser.error('invalid port, interval or collector identifier')
    token = os.environ.get('AEGIS_API_TOKEN', '')
    if not token:
        print('AEGIS_API_TOKEN is required.', file=sys.stderr)
        return 2
    try:
        events = json.loads(FIXTURE.read_text(encoding='utf-8'))['events']
        run = uuid.uuid4().hex
        for attempt in range(args.retries + 1):
            try:
                post(args.port, f'/api/v1/collectors/{args.collector_id}/heartbeat', {'state': 'running'}, token)
                break
            except urllib.error.HTTPError as exc:
                if exc.code < 500 or attempt == args.retries:
                    raise
            except (OSError, urllib.error.URLError):
                if attempt == args.retries:
                    raise
            print('Synthetic collector could not report its start; retrying.', file=sys.stderr)
            time.sleep(args.retry_delay)
        for index, event in enumerate(events):
            body = {'events': [event]}
            headers = {'X-Collector-ID': args.collector_id, 'Idempotency-Key': f'fixture-{run}-{index}'}
            for attempt in range(args.retries + 1):
                try:
                    result = post(args.port, '/api/v1/ingest/sysmon', body, token, headers)
                    break
                except urllib.error.HTTPError as exc:
                    if exc.code < 500 or attempt == args.retries:
                        raise
                except (OSError, urllib.error.URLError):
                    if attempt == args.retries:
                        raise
                print(f'Synthetic event {index + 1} not acknowledged; retrying.', file=sys.stderr)
                try:
                    post(args.port, f'/api/v1/collectors/{args.collector_id}/heartbeat',
                         {'state': 'error', 'error_code': 'send_error'}, token)
                except (OSError, ValueError, urllib.error.URLError):
                    pass
                time.sleep(args.retry_delay)
            if not result.get('analysis_id'):
                raise ValueError('missing acknowledgement')
            summary = result.get('summary')
            if not isinstance(summary, dict):
                raise ValueError('missing summary')
            processed = summary.get('processed')
            duplicate = summary.get('duplicate', 0)
            if type(processed) is not int or type(duplicate) is not int:
                raise ValueError('invalid summary')
            print(f'Synthetic event {index + 1}/{len(events)} acknowledged; processed={processed}, duplicate={duplicate}')
            if attempt:
                try:
                    post(args.port, f'/api/v1/collectors/{args.collector_id}/heartbeat', {'state': 'running'}, token)
                except (OSError, ValueError, urllib.error.URLError):
                    print('Collector recovery heartbeat failed.', file=sys.stderr)
            if index + 1 < len(events):
                time.sleep(args.interval)
        post(args.port, f'/api/v1/collectors/{args.collector_id}/heartbeat', {'state': 'stopped'}, token)
        return 0
    except urllib.error.HTTPError as exc:
        print(f'Local collector request failed (HTTP {exc.code}).', file=sys.stderr)
    except (OSError, KeyError, ValueError, urllib.error.URLError):
        print('Local collector could not read the fixture or connect to the server.', file=sys.stderr)
    try:
        post(args.port, f'/api/v1/collectors/{args.collector_id}/heartbeat',
             {'state': 'error', 'error_code': 'send_error'}, token)
    except (OSError, ValueError, urllib.error.URLError):
        pass  # The server may be unreachable; do not echo its response.
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
