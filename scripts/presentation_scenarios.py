"""Send project-authored fictional observations to the local demo server only.

These records are test input, not events collected from a real PC or service.
No displayed command is executed. The one-time collector credential is read
from the environment and is never printed or accepted as a command argument.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import os
import re
import sys
import urllib.error
from uuid import uuid4

from collect_synthetic import post


def _sysmon(kind: int, record_id: int, host: str, when: datetime, destination: str = '') -> dict:
    # Strings are fictional input to the normalizer, never executed.
    data = {
        'UtcTime': when.strftime('%Y-%m-%d %H:%M:%S.%f'),
        'Image': r'C:\Windows\System32\whoami.exe' if kind == 1 else r'C:\Windows\System32\svchost.exe',
        'User': r'DEMO\fictional-user',
        'ProcessGuid': '{' + str(uuid4()) + '}', 'ProcessId': 1000 + record_id % 10000,
    }
    if kind == 1:
        data.update({'CommandLine': 'whoami /groups', 'ParentImage': r'C:\Windows\explorer.exe'})
    else:
        data.update({'SourceIp': '192.0.2.10', 'SourcePort': 50000,
                     'DestinationIp': destination, 'DestinationPort': 443, 'Initiated': True})
    return {'System': {'Provider': 'Microsoft-Windows-Sysmon', 'EventID': kind,
                       'TimeCreated': when.isoformat(), 'Computer': host,
                       'EventRecordID': record_id,
                       'Channel': 'Microsoft-Windows-Sysmon/Operational'}, 'EventData': data}


def build_batches(scenario: str, run_id: str, start: datetime) -> list[tuple[str, dict]]:
    """Construct observations with unique source IDs and separate host groups."""
    # A 60-bit random base with room for three distinct records stays in SQLite's
    # signed 64-bit range. A fresh run also receives a different fictional host.
    base = (int(run_id[:15], 16) << 2) + 1
    if scenario == 'normal':
        host = 'DEMO-NORMAL-' + run_id[:12]
        return [('sysmon', {'events': [_sysmon(1, base, host, start)]})]
    if scenario == 'auth':
        host = 'DEMO-AUTH-' + run_id[:12]
        records = [{'event_id': f'{run_id}-{i}', 'timestamp': (start + timedelta(minutes=i)).isoformat(),
                    'host': host, 'account': 'fictional-account', 'source_ip': '192.0.2.1',
                    'outcome': 'success' if i == 3 else 'failure'} for i in range(4)]
        # Deliberately split evidence across two separately acknowledged batches.
        return [('auth', {'events': records[:3]}), ('auth', {'events': records[3:]})]
    if scenario == 'fanout':
        host = 'DEMO-NET-' + run_id[:12]
        return [('sysmon', {'events': [_sysmon(3, base + i, host, start + timedelta(minutes=i),
                                               f'198.51.100.{i + 1}')]}) for i in range(3)]
    raise ValueError('invalid scenario')


def send_scenario(scenario: str, port: int, collector_id: str, token: str) -> None:
    run_id = uuid4().hex
    start = datetime.now(timezone.utc) - timedelta(minutes=4)
    batches = build_batches(scenario, run_id, start)
    for index, (kind, body) in enumerate(batches):
        # collect_synthetic.post disables proxy and redirects and fixes the host
        # at 127.0.0.1. No raw response or exception content is displayed.
        result = post(port, f'/api/v1/ingest/{kind}', body, token,
                      {'X-Collector-ID': collector_id, 'Idempotency-Key': f'demo-{run_id}-{index}'})
        summary = result.get('summary')
        if (not result.get('analysis_id') or not isinstance(summary, dict)
                or summary.get('processed') != len(body['events']) or summary.get('duplicate', 0) != 0):
            raise ValueError('unexpected acknowledgement')
        print(f'가상 {scenario}: 배치 {index + 1}/{len(batches)} 수신 확인 ({summary["processed"]}건)')
    print('저장된 이벤트와 탐지 근거는 로그인한 관제 화면에서 확인하세요. 실제 공격이나 차단은 수행하지 않았습니다.')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scenario', choices=('normal', 'auth', 'fanout'))
    parser.add_argument('--collector-id', default='demo-collector')
    parser.add_argument('--port', type=int, default=8000)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', args.collector_id):
        parser.error('invalid port or collector identifier')
    token = os.environ.get('AEGIS_COLLECTOR_TOKEN', '')
    if not token:
        print('AEGIS_COLLECTOR_TOKEN을 안전하게 설정하세요.', file=sys.stderr)
        return 2
    try:
        send_scenario(args.scenario, args.port, args.collector_id, token)
    except urllib.error.HTTPError as exc:
        print(f'로컬 서버가 배치를 거부했습니다 (HTTP {exc.code}). 상세 원문은 출력하지 않습니다.', file=sys.stderr)
        return 1
    except (OSError, ValueError, urllib.error.URLError):
        print('로컬 서버 연결 또는 배치 수신 확인에 실패했습니다.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
