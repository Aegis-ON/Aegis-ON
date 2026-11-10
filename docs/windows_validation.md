# Windows Sysmon 로컬 검증 절차

이 절차는 실제 Windows에서 **아직 실행하거나 검증하지 않았습니다**. Sysmon이 설치되지 않았거나 서비스가 실행 중이 아니면 실제 수집은 진행하지 않습니다. 합성 입력은 API 형식과 모델 로딩 확인용이며, 실제 공격 탐지율을 검증하지 않습니다. 실험용 명령 분류 모델은 PII 모델과 별개이고 기본적으로 비활성화되어 있습니다. API 서버는 모델 하나씩 순차 실행합니다. 아래 로컬 비교 도구는 별도 프로세스에서 두 모델을 함께 로드합니다.

Sysmon 설치, 서비스 시작, 설정 변경, 로깅 정책 변경 또는 공격 명령 실행을 이 절차에 포함하지 않습니다. 접근 권한이 없다면 실패로 기록하고 중단합니다. 로컬 로그, 원본 명령줄, 계정, 호스트명, IP, 파일 경로 및 응답에는 민감정보가 있을 수 있습니다. 외부에 전송하지 않고 Git 저장소와 동기화 폴더 밖의 본인만 접근 가능한 로컬 디렉터리에 보관하세요. 가명처리는 완전한 익명화를 보장하지 않습니다. 로그나 응답 전문, 환경변수, 토큰 및 경로를 공유하거나 커밋하지 마세요.

## 사전 조건과 상태 확인

Windows PowerShell을 저장소 루트에서 실행합니다. `README.md`의 Windows 가상환경 설정을 따르고, 명령 모델을 사용하려면 추가로 다음 의존성을 설치합니다. 설치에는 패키지 저장소 접속이 필요하며 로그를 전송하지 않습니다.

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-attack.txt
```

설치된 Sysmon 서비스와 로그 채널을 **읽기 전용**으로 확인합니다. 서비스 이름은 설치 방식에 따라 다를 수 있습니다. 아무것도 반환되지 않거나 `Stopped`이면 미설치 또는 미실행으로 기록하고 수집을 중단하세요. 채널 조회 오류는 권한 또는 채널 접근 실패입니다. 이 결과만으로 설치 여부를 단정하지 않습니다.

```powershell
Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue |
    Select-Object Name, Status
try {
    $channel = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
    if (-not $channel.IsEnabled) { throw 'Sysmon channel disabled' }
    Write-Host 'PASS: Sysmon operational channel accessible and enabled'
} catch {
    Write-Host 'FAIL: Sysmon channel unavailable, disabled, or access denied'
    throw
}
```

Event ID 3 수집은 Sysmon 설정에 따라 비활성화되거나 필터링될 수 있습니다. 이미 설치된 Sysmon 실행 파일의 `-c`로 현재 설정을 확인하거나 담당 관리자가 확인하도록 요청하세요. 설정 내용은 민감할 수 있으므로 화면 밖으로 저장하거나 공유하지 않습니다. **설정을 적용하는 명령은 사용하지 않습니다.** 설정 내 NetworkConnect 규칙의 포함·제외 조건을 직접 확인해야 하며, 규칙이 있어도 특정 연결이 반드시 기록되는 것은 아닙니다. 기존 Event 3이 있는지 아래 읽기 전용 검사로 확인할 수 있습니다. 최근 이벤트가 없다는 결과는 설정 비활성화의 증거가 아닙니다. 연결을 새로 만들거나 대상 네트워크에 접근할 필요는 없습니다.

예를 들어 이미 설치된 실행 파일의 경로를 알고 있고 열람 권한이 있을 때만 `& '<설치된 Sysmon 실행 파일 경로>' -c`로 현재 설정을 로컬에서 확인합니다. 출력에는 운영 정책이 포함될 수 있습니다. 설치나 `-c <설정 파일>` 적용은 하지 않으며, 변경이 필요하다면 영향을 검토한 관리자가 별도로 결정해야 합니다.

```powershell
try {
    $recent3 = @(Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 3
    } -MaxEvents 1 -ErrorAction Stop)
    if ($recent3.Count -gt 0) { Write-Host 'PASS: an existing Event 3 is present' }
} catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
        Write-Host 'NOT OBSERVED: no existing Event 3; configuration and filters remain unverified'
    } else {
        Write-Host 'FAIL: Event 3 query failed or access denied'
        throw
    }
}
```

## 모델을 하나씩 실행

두 체크포인트를 서로 다른 보호된 로컬 디렉터리에 준비합니다. 원본 및 개선 모델의 6개 파일과 매니페스트를 신뢰할 수 있는 별도 해시와 비교하세요. 모델 옆에 놓인 매니페스트만으로 출처를 증명할 수 없습니다. 보존된 Drive 사본은 다운로드 후 해시 확인이 별도로 필요합니다. 원본 가중치 SHA-256은 `c33ad158789d3b57d60947ac89346ade3eec16c0045b381356fed423c025bf28`, 개선 가중치는 `bff7da13980f8c939c63d102c33a7143e90e3113182b9ebdc9116889255d0432`입니다.

PII NER은 이 두 명령 분류기와 별도입니다. 기본적으로 비활성화되어 정규식만 적용되며, 선택적으로 설치하려면 [PII 모델 안내](pii_model.md)의 고정 버전과 해시를 확인한 뒤 `AEGIS_PII_MODEL_DIR`을 로컬 경로로 설정하세요. 응답의 `pii.state`를 확인하고 모델이 필요한 검증에서 `ready`가 아니면 해당 검증을 미실행으로 기록합니다. 정규식 또는 모델은 모두 개인정보를 놓칠 수 있습니다.

압축을 푼 위치와 실제 파일을 확인하세요. 원본 보존 ZIP의 매니페스트는 모델 폴더와 별도의 `metadata.json`이고, 개선 모델의 매니페스트는 모델 폴더 안의 `manifest.json`입니다. 모델 디렉터리는 여섯 모델 파일이 **직접 들어 있는 폴더**로 지정합니다. 매니페스트 경로를 모델 디렉터리로 착각하거나 두 모델의 매니페스트를 서로 바꾸면 로드에 실패합니다. 압축 구조를 임의로 가정하지 말고 각 파일을 확인하세요.

각 파일의 실제 SHA-256을 두 매니페스트와 비교하려면, 아래 네 변수를 자신의 경로로 설정하고 실행하세요. 매니페스트 자체도 **별도로 신뢰한 해시와 대조한 후** 사용합니다. 이 검사는 파일의 일치를 확인하며 출처를 인증하지 않습니다. 성공할 때 경로와 매니페스트 내용을 출력하지 않습니다. PowerShell 오류에는 로컬 경로가 포함될 수 있으므로 오류 화면과 콘솔 기록도 공유하지 마세요.

```powershell
$OriginalDir = '<원본 여섯 파일이 들어 있는 폴더>'
$OriginalManifest = '<원본 metadata.json 경로>'
$RefinedDir = '<개선 여섯 파일이 들어 있는 폴더>'
$RefinedManifest = '<개선 모델 폴더의 manifest.json 경로>'
$files = @('model.safetensors', 'config.json', 'tokenizer.json',
    'tokenizer_config.json', 'special_tokens_map.json', 'vocab.txt')
foreach ($pair in @(@($OriginalDir, $OriginalManifest), @($RefinedDir, $RefinedManifest))) {
    $manifest = Get-Content -LiteralPath $pair[1] -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($name in $files) {
        $expectedHash = $manifest.sha256.$name
        $actualHash = (Get-FileHash -LiteralPath (Join-Path $pair[0] $name) -Algorithm SHA256).Hash
        if (-not $expectedHash -or $actualHash -ne $expectedHash) { throw 'FAIL: artifact hash mismatch' }
    }
}
if ((Get-FileHash -LiteralPath (Join-Path $OriginalDir 'model.safetensors') -Algorithm SHA256).Hash -ne
    'c33ad158789d3b57d60947ac89346ade3eec16c0045b381356fed423c025bf28' -or
    (Get-FileHash -LiteralPath (Join-Path $RefinedDir 'model.safetensors') -Algorithm SHA256).Hash -ne
    'bff7da13980f8c939c63d102c33a7143e90e3113182b9ebdc9116889255d0432') { throw 'FAIL: unexpected model weights' }
Write-Host 'PASS: six artifacts per model match their manifests and expected weights'
```

서버 PowerShell에서 다음 경로를 자신의 로컬 경로로 바꿉니다. 기억할 수 있는 충분히 긴 무작위 토큰을 보안 입력으로 입력하며 화면에 출력하거나 파일에 저장하지 않습니다. 요청 세션에서도 같은 토큰을 입력합니다. 바인딩은 루프백으로 제한하고, 자동 재시작은 사용하지 않습니다.

```powershell
$serverToken = Read-Host '로컬 서버 토큰' -AsSecureString
$serverCredential = [System.Management.Automation.PSCredential]::new('analyst', $serverToken)
$env:AEGIS_API_TOKEN = $serverCredential.GetNetworkCredential().Password
$env:AEGIS_ANALYST_NAME = 'analyst-1'
$env:AEGIS_ATTACK_MODEL_DIR = '<원본 모델 디렉터리>'
$env:AEGIS_ATTACK_MODEL_MANIFEST = '<원본 매니페스트 파일>'
.\.venv\Scripts\python.exe -m uvicorn --app-dir src aegis_on.api:app --host 127.0.0.1 --port 8000
```

같은 PowerShell에서 서버를 종료한 뒤 `AEGIS_ATTACK_MODEL_DIR`과 `AEGIS_ATTACK_MODEL_MANIFEST`를 개선 모델의 경로로 바꾸고 동일한 명령으로 재시작합니다. 모델은 서버 시작 때 로드되므로 실행 중 환경변수 변경만으로 교체되지 않습니다. 두 번 모두 인증된 `/api/v1/attack-model/status`에서 `state=ready`와 해당 가중치 해시를 확인하고, 준비되지 않았거나 해시가 다르면 실패로 중단하세요. 요청을 보내는 별도 PowerShell에는 **동일한** 토큰을 안전하게 설정해야 합니다. 다른 서버나 인터넷 주소를 대상으로 지정하지 마세요.

```powershell
# 별도 요청 세션: 토큰은 신뢰할 수 있는 로컬 방법으로 입력하고 화면에 표시하지 않습니다.
$tokenSecure = Read-Host '로컬 서버 토큰' -AsSecureString
$credential = [System.Management.Automation.PSCredential]::new('analyst', $tokenSecure)
$headers = @{ Authorization = 'Bearer ' + $credential.GetNetworkCredential().Password }
$status = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/v1/attack-model/status' -Headers $headers
if ($status.state -ne 'ready') { throw 'FAIL: model is not ready' }
# 비교할 모델에 맞는 해시를 선택합니다.
$expected = '<위의 해당 모델 가중치 SHA-256>'
if ($status.weights_sha256 -ne $expected) { throw 'FAIL: unexpected model weights' }
Write-Host 'PASS: model ready and expected weights loaded'
```

서버 세션과 요청 세션에 같은 토큰을 입력합니다. 토큰이 없거나 인증되지 않은 경우 성공으로 간주하지 않습니다.

## Event 1 생성과 보호된 내보내기

본인에게 수집 권한이 있는 테스트 Windows에서만 아래 정상 명령을 실행합니다. 이는 무해한 문자열을 출력하는 프로세스 생성이며 공격 동작을 수행하지 않습니다. 실행 후 기존 내보내기 스크립트가 최근 Event 1과 3을 읽습니다. 이 스크립트는 테스트 이벤트만 읽지 않으므로 **다른 사용자의 이벤트와 원본 개인정보도 파일에 포함할 수 있습니다**. 수집이 허용되지 않으면 실행하지 마세요. 실제 사용자 활동이 없는 네트워크 연결을 강제로 만들지 않습니다.

먼저 `$PrivateDir`을 저장소 및 동기화 폴더 밖의 접근 통제된 로컬 디렉터리로 지정하고, 상위 폴더와 파일 권한을 직접 확인하세요. 내보내기는 기존 출력 파일을 거부하고 JSON이 2 MiB를 초과할 것으로 예상되면 파일을 만들지 않습니다. 이 검사는 실제 Windows PowerShell에서 아직 실행하지 않았습니다. 아래 코드는 내보내기 스크립트의 경로 출력을 숨기고, 실패 시 성공으로 표시하지 않습니다.

```powershell
$PrivateDir = '<저장소 밖의 접근 통제된 빈 로컬 디렉터리>'
if (-not (Test-Path -LiteralPath $PrivateDir -PathType Container)) { throw 'FAIL: private directory unavailable' }
$RawFile = Join-Path $PrivateDir 'sysmon-raw.json'
if (Test-Path -LiteralPath $RawFile) { throw 'FAIL: output already exists' }
& $env:ComSpec /d /c 'echo AEGIS_ON_VALIDATION_EVENT1'
# 선택적 정상 PowerShell 실행도 별도 Event 1로 발생시킵니다.
& powershell.exe -NoProfile -Command "Write-Output 'AEGIS_ON_VALIDATION_POWERSHELL'"
try {
    & .\scripts\export_sysmon.ps1 -OutputPath $RawFile -MaxEvents 500 *> $null
    if (-not (Test-Path -LiteralPath $RawFile -PathType Leaf)) { throw 'missing output' }
    Write-Host 'PASS: export created in private directory'
} catch {
    Write-Host 'FAIL: export failed; check Sysmon access and events locally'
    throw 'Sysmon export failed'
}
```

생성 이벤트가 필터에 걸리거나 500개 범위 밖이면 검증 실패입니다. 원본 전체를 출력하지 말고 아래처럼 표시용 마커가 있는 Event 1 한 건만 선택해 별도 입력 파일을 만듭니다. 그래도 선택 이벤트의 사용자·부모 프로세스·호스트명 등은 실제 값이므로 동일하게 보호합니다. 선택된 이벤트와 원본 파일은 필요한 보존 기간이 끝나면 로컬 정책에 따라 삭제하세요. 실수로 다른 사람의 데이터가 수집됐다면 공유하지 말고 해당 파일을 처리 정책에 따라 삭제합니다.

```powershell
$EventFile = Join-Path $PrivateDir 'event1-selected.json'
if (Test-Path -LiteralPath $EventFile) { throw 'FAIL: selected output already exists' }
$batch = Get-Content -LiteralPath $RawFile -Raw -Encoding UTF8 | ConvertFrom-Json
$selected = @($batch.events | Where-Object {
    $_.System.EventID -eq 1 -and $_.EventData.CommandLine -like '*AEGIS_ON_VALIDATION_EVENT1*'
} | Select-Object -First 1)
if ($selected.Count -ne 1) { throw 'FAIL: test Event 1 not found in export' }
ConvertTo-Json -InputObject @{ events = $selected } -Depth 6 |
    Set-Content -LiteralPath $EventFile -Encoding UTF8
Write-Host 'PASS: selected one matching Event 1'
```

최근에 같은 마커로 실행한 이벤트가 여러 개라면 선택 항목이 이번 실행의 항목인지 로컬에서 시각을 확인하세요. 포함된 다른 필드와 전문을 외부로 복사하지 않습니다. Event 3은 사용자의 정상 활동에서 이미 관찰된, 수집 권한이 있는 사건이 있을 때만 선택적으로 검증합니다. 없거나 필터에 제외됐다면 `NOT OBSERVED`로 남기고 성공이나 실패로 꾸미지 않습니다.

PowerShell 프로세스도 확인하려면 위의 선택 필터에서 마커를 `AEGIS_ON_VALIDATION_POWERSHELL`로 바꾸고 **다른 출력 파일명**을 사용하세요. `Get-Date` 등 PowerShell 내부 명령 자체는 별도의 프로세스가 아니므로 각각 Sysmon Event 1을 만든다고 가정하지 않습니다.

### Event 3: 기존 본인 활동 또는 선택적 루프백

이미 존재하는 Event 3 중 본인에게 수집 권한이 있고 본인이 발생시킨 정상 활동만 선택하세요. 예를 들어 활동 직전의 UTC 시각과 해당 프로세스 ID를 별도로 알고 있을 때, 앞서 만든 `$batch`를 메모리에서 필터링할 수 있습니다. 아래 예의 값은 실제 활동의 값으로 교체해야 하며, 타인의 이벤트를 선택하지 않습니다. PID가 재사용될 수 있으므로 시각과 본인의 활동을 함께 확인해야 합니다. 원본 필드를 출력하거나 공유하지 않습니다. 조건에 맞는 것이 없으면 미관측으로 두세요.

```powershell
$OwnProcessId = '<본인 활동의 프로세스 ID>'
$OwnStartUtc = [DateTime]::Parse('<활동 시작 UTC 시각>').ToUniversalTime()
$OwnEndUtc = [DateTime]::Parse('<활동 종료 UTC 시각>').ToUniversalTime()
$ownNetwork = @($batch.events | Where-Object {
    $_.System.EventID -eq 3 -and $_.EventData.ProcessId -eq $OwnProcessId -and
    [DateTimeOffset]::Parse($_.System.TimeCreated).UtcDateTime -ge $OwnStartUtc -and
    [DateTimeOffset]::Parse($_.System.TimeCreated).UtcDateTime -le $OwnEndUtc
})
if ($ownNetwork.Count -eq 0) { Write-Host 'NOT OBSERVED: owned Event 3 not found' }
else { Write-Host 'REVIEW: confirm the selected events belong to your authorized activity locally' }
```

실험자가 **원하는 경우에만**, 사용자 외부 활동을 만들지 않는 단일 컴퓨터의 `127.0.0.1` 루프백에서 정상 TCP 연결을 만들 수 있습니다. 대상 시스템이나 외부 네트워크에 연결하지 않습니다. 다음을 같은 PowerShell에서 실행하면 임시 리스너는 무작위 포트에 열렸다가 종료됩니다. 이는 선택 사항이며, 관찰 결과는 현재 Sysmon 정책과 필터에 따라 달라집니다.

```powershell
$loopbackStartUtc = [DateTime]::UtcNow
$loopbackPid = "$PID"
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$client = [System.Net.Sockets.TcpClient]::new()
try {
    $listener.Start()
    $client.Connect([System.Net.IPAddress]::Loopback, $listener.LocalEndpoint.Port)
    Write-Host 'PASS: local loopback connection completed'
} finally {
    $client.Dispose()
    $listener.Stop()
}
$loopbackEndUtc = [DateTime]::UtcNow
```

연결 후 위의 기존 내보내기 절차를 **새 파일 이름**으로 반복하고 새 `$batch`를 읽습니다. `$OwnProcessId = $loopbackPid`, `$OwnStartUtc = $loopbackStartUtc`, `$OwnEndUtc = $loopbackEndUtc`를 설정해 위의 필터를 적용하고 목적지가 `127.0.0.1`인 본인 활동인지 로컬에서 확인합니다. 이벤트가 없으면 `NOT OBSERVED`입니다. 선택한 이벤트를 별도 보호 파일로 만드는 경우, `@{ events = @($ownNetwork) }`를 `ConvertTo-Json -Depth 6`으로 직렬화하고 기존 파일을 덮어쓰지 마세요. 둘 이상의 서로 다른 이벤트를 추가하려면 로컬에서 정확한 항목을 확인하고 배열에 넣습니다.

## 분석과 판정

두 모델 실행에서 **같은** 선택 이벤트 파일 또는 저장소의 합성 `data/demo_sysmon.json`을 각각 한 번씩 로컬 `/api/v1/sysmon/analyze`에 보냅니다. 응답 전문은 출력하거나 파일에 저장하지 않고, 아래와 같이 메모리에서 검증한 뒤 제거합니다. HTTP 오류, 크기 제한 2 MiB 초과, 파싱 오류, 모델 `error`/`disabled`/`model_unavailable`, 개별 이벤트 오류는 명시적인 실패 또는 미평가입니다. `below_threshold`는 안전이나 공격 부재를 증명하지 않습니다.

### 로컬 API 요청과 연결 검사

요청 세션의 `$headers`와 보호된 `$EventFile`을 사용합니다. 개인정보 가명처리 및 의심 사례 검증용 합성 입력은 `$InputFile = 'data/windows_validation_synthetic.json'`, 실제 정상 입력은 `$InputFile = $EventFile`로 별도 실행하세요. 합성 파일은 가상 이메일·문서용 IP와 가상 다운로드 문자열을 포함하며 실제 개인정보나 실제 공격 기록이 아닙니다. API와 비교 도구의 제한은 각각 2 MiB입니다. 크기 초과는 실패이며 로그를 임의로 잘라 JSON을 손상시키지 마세요. 권한 있는 이벤트만 선택해 더 작은 유효한 배치로 다시 만듭니다.

```powershell
$InputFile = $EventFile  # 합성만 확인할 때는 'data/windows_validation_synthetic.json'
if ((Get-Item -LiteralPath $InputFile).Length -gt 2MB) { throw 'FAIL: input exceeds 2 MiB' }
try {
    $response = Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/api/v1/sysmon/analyze' `
        -Headers $headers -ContentType 'application/json' -InFile $InputFile
    if ($response.summary.invalid -gt 0 -or $response.summary.unsupported -gt 0) {
        throw 'invalid or unsupported events'
    }
    if ($response.attack_model.state -ne 'ready') { throw 'model unavailable or inference failed' }
    Write-Host "PII model state: $($response.pii.state) (disabled/error means regex-only)"
    if (@($response.source_events).Count -ne $response.summary.processed) { throw 'source count mismatch' }
    foreach ($source in $response.source_events) {
        $item = @($response.items | Where-Object { $_.input_index -eq $source.input_index -and $_.status -eq 'processed' })
        if ($item.Count -ne 1 -or $item[0].event_id -ne $source.event_id) { throw 'source mapping mismatch' }
    }
    foreach ($finding in $response.pii.findings) {
        $source = @($response.source_events | Where-Object { $_.input_index -eq $finding.input_index })
        if ($source.Count -ne 1 -or $source[0].event_id -ne $finding.event_id) { throw 'PII mapping mismatch' }
    }
    foreach ($detection in $response.detections) {
        foreach ($eventId in $detection.event_ids) {
            if (@($response.source_events | Where-Object { $_.event_id -eq $eventId }).Count -ne 1) {
                throw 'detection mapping mismatch'
            }
        }
    }
    $modelResults = @($response.attack_model.results)
    if ($modelResults.Count -ne $response.summary.processed -or
        @($modelResults | Select-Object -ExpandProperty input_index -Unique).Count -ne $response.summary.processed) {
        throw 'model result count mismatch'
    }
    foreach ($modelResult in $modelResults) {
        $source = @($response.source_events | Where-Object { $_.input_index -eq $modelResult.input_index })
        if ($source.Count -ne 1 -or $source[0].event_id -ne $modelResult.event_id) {
            throw 'model result mapping mismatch'
        }
    }
    if (@($response.pii.findings).Count -eq 0) {
        Write-Host 'NOT OBSERVED: no PII finding to test its input_index link'
    } else { Write-Host 'PASS: observed PII findings link to source events' }
    $unscoredCount = @($response.attack_model.results | Where-Object { $_.status -ne 'ok' }).Count
    Write-Host "Model inputs not scored: $unscoredCount"
    Write-Host 'PASS: request, model state, and processed source links checked'
} catch {
    Write-Host 'FAIL: request or result validation failed'
    throw 'Local API validation failed'
} finally {
    Remove-Variable response -ErrorAction SilentlyContinue
}
```

입력별 모델의 `missing_command`, `too_long` 등 비정상 추론 상태는 미평가이며, 정상 처리된 모든 항목이 모델에서 성공했다고 의미하지 않습니다. 필요하면 원문을 출력하지 않고 상태 개수만 메모리에서 확인하세요. PII finding이 없으면 해당 연결은 미관측이고, 합성 예제의 IP 탐지 결과도 PII 전체 보호를 증명하지 않습니다. 서버 콘솔과 API 오류 메시지, 응답을 외부로 보내지 않습니다.

### 로컬 배치 비교

다음 도구는 API 서버를 사용하지 않고 저장된 두 모델을 로컬 프로세스에 로드하여 같은 Sysmon JSON 배치를 비교합니다. 원본 로그와 합성 입력을 **별도 실행 및 별도 결과**로 유지하세요. `--source`는 사용자의 선언일 뿐 입력이 정상 또는 합성임을 자동으로 인증하지 않습니다. 원본 로그는 접근 권한과 동의가 있는 정상 활동만 사용합니다. 출력은 원본 이벤트 필드나 경로를 포함하지 않도록 설계되었지만, 인덱스와 탐지 신호도 민감할 수 있고 PII의 완전한 보호를 보장하지 않습니다. 표준 출력과 결과 파일도 보호하고 공유하지 마세요.

아래 경로를 자신의 경로로 바꿉니다. `$EventFile`과 `$PrivateDir`은 앞 단계에서 설정한 값입니다. 예시는 결과 파일이 이미 있으면 중단합니다. 오류가 나면 결과를 성공으로 간주하지 않습니다.

```powershell
$OriginalDir = '<원본 여섯 파일이 들어 있는 폴더>'
$OriginalManifest = '<원본 metadata.json 경로>'
$RefinedDir = '<개선 여섯 파일이 들어 있는 폴더>'
$RefinedManifest = '<개선 모델 폴더의 manifest.json 경로>'
$env:PYTHONPATH = 'src'
$LocalReport = Join-Path $PrivateDir 'local-normal-comparison.json'
if (Test-Path -LiteralPath $LocalReport) { throw 'FAIL: output already exists' }
$result = & .\.venv\Scripts\python.exe -m aegis_on.windows_validation `
    --input $EventFile --source local-normal `
    --original-dir $OriginalDir --original-manifest $OriginalManifest `
    --refined-dir $RefinedDir --refined-manifest $RefinedManifest
if ($LASTEXITCODE -ne 0) { throw 'FAIL: local comparison failed' }
$result | Set-Content -LiteralPath $LocalReport -Encoding UTF8
Write-Host 'PASS: local comparison saved privately'
```

합성 배치는 같은 명령에서 `--input data/windows_validation_synthetic.json --source synthetic`으로 바꾸고 다른 보호된 결과 파일에 저장합니다. API 서버용 `AEGIS_ATTACK_MODEL_DIR`과 `AEGIS_ATTACK_MODEL_MANIFEST`는 서버 시작 전 해당 모델로 설정해야 합니다. 비교 도구는 위 네 경로 인자를 사용하며, 기존 환경변수만 바꾸는 것으로 두 모델을 선택하지 않습니다.

결과의 `cases`는 원본 배열의 0부터 시작하는 `input_index`와 처리 상태를 표시합니다. `paired_event1.events`는 두 모델이 모두 정상 추론한 처리된 Event 1의 수이고, 그 아래 `rule`, `keyword`, `baseline`, `original`, `refined`는 **그 동일한 분모**에서 검토 신호가 발생한 이벤트 수입니다. `baseline`은 규칙 또는 키워드 신호이며 둘은 겹칠 수 있습니다. `methods`의 방법별 전체 적격 건수는 다를 수 있으므로 동일 분모의 비교로 해석하지 않습니다. `missing_command`, `too_long` 등은 해당 모델의 미평가 상태로 별도 집계하며 음성으로 취급하지 않습니다. 모델 로딩 실패 또는 문서 전체가 유효하지 않으면 도구가 실패합니다. 개별 이벤트의 오류나 미지원은 각각 `invalid` 또는 `unsupported`로 결과에 표시하고 다른 유효 이벤트는 처리합니다. 연결 이벤트를 포함할 수는 있지만 이 도구에는 팬아웃 등 상관분석이 포함되지 않습니다. 정상 로그에는 정답 공격 사례가 없으므로 재현율이나 공격률을 추정할 수 없습니다.

원본 명령줄과 탐지 결과를 확인하는 동안 개인정보가 화면 또는 로그에 노출될 수 있습니다. 응답과 서버 로그를 공유하지 말고, 단일 로컬 컴퓨터의 액세스 통제를 유지하세요. Event 1의 파싱과 이벤트 연결, 모델 상태 및 입력별 결과를 확인하되 이 정상 활동이 경고되지 않았다는 사실로 탐지 품질을 주장하지 않습니다. Event 3을 관찰하지 못했으면 Event 3 경로는 미검증으로 남깁니다. 실험 종료 시 서버를 중지하고 세션의 토큰과 모델 환경변수를 제거합니다.
