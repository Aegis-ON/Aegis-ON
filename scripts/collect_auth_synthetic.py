"""Send a fictional authentication sequence to a local server, never a remote host."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import os
import re
import sys
import urllib.error
from uuid import uuid4

from collect_synthetic import post


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--collector-id', default='synthetic-collector')
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', args.collector_id):
        parser.error('invalid port or collector identifier')
    token = os.environ.get('AEGIS_COLLECTOR_TOKEN', '')
    if not token:
        print('AEGIS_COLLECTOR_TOKEN is required.', file=sys.stderr)
        return 2
    run = uuid4().hex
    start = datetime.now(timezone.utc) - timedelta(minutes=4)
    records = [{'event_id': f'{run}-{i}', 'timestamp': (start + timedelta(minutes=i)).isoformat(),
                'host': 'demo-auth-server', 'account': 'demo-user', 'source_ip': '192.0.2.1',
                'outcome': 'success' if i == 3 else 'failure'} for i in range(4)]
    try:
        result = post(args.port, '/api/v1/ingest/auth', {'events': records}, token,
                      {'X-Collector-ID': args.collector_id, 'Idempotency-Key': f'auth-{run}'})
        if not result.get('analysis_id'):
            raise ValueError('missing acknowledgement')
        print('Fictional authentication batch acknowledged.')
        return 0
    except (OSError, ValueError, urllib.error.URLError):
        print('Local authentication demonstration failed.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
