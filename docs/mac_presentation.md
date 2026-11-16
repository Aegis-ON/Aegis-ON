# Mac 가상 데이터 관제 시연

이 시연은 실제 공격이나 Windows 수집기를 실행하지 않습니다. 프로그램이 만든 **가상 이벤트**를 루프백 서버로 전송해 수집·분석·탐지 근거 확인 과정을 보여줍니다. 분석가의 승인은 실제 차단이 아닌 **시뮬레이션**입니다. 인증 기록과 Sysmon 기록은 이 시연에서 서로 다른 가상 출처이며, 같은 사용자·PC나 하나의 사건이라고 연결하지 않습니다.

## 준비: 이 시연 전용 임시 DB

PR #18을 포함하고 이 문서와 `scripts/presentation_scenarios.py`가 있는 브랜치에서 실행합니다. 실제 운영 DB나 기존 인증 정보를 사용하지 않습니다. 아래 명령은 **새 터미널**에서 실행하고, 가상환경에 `requirements.txt` 의존성이 설치돼 있어야 합니다. `python`은 해당 가상환경의 Python입니다. 서버와 클라이언트는 같은 Mac의 `127.0.0.1`만 사용하세요.

```zsh
# 저장소 루트에서 시작합니다. 기존 파일을 덮어쓰지 않는 새 임시 폴더입니다.
AEGIS_DEMO_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-presentation.XXXXXXXX")"
chmod 700 "$AEGIS_DEMO_DIR"
export AEGIS_DEMO_DIR
export AEGIS_HISTORY_DB="$AEGIS_DEMO_DIR/history.sqlite3"
export AEGIS_AUTH_DB="$AEGIS_DEMO_DIR/sessions.sqlite3"
export AEGIS_LOGIN_USERNAME='demo-analyst'
export AEGIS_ANALYST_NAME='demo-analyst'
export AEGIS_SESSION_TTL_SECONDS=3600
# 모델 훈련·추론과 기존 공유 수집기 토큰을 사용하지 않습니다.
unset AEGIS_ATTACK_MODEL_DIR AEGIS_ATTACK_MODEL_MANIFEST AEGIS_PII_MODEL_DIR
unset AEGIS_CODEBERT_SHADOW_DIR AEGIS_CODEBERT_SHADOW_MANIFEST_SHA256
unset AEGIS_API_TOKEN AEGIS_ALLOW_LEGACY_COLLECTOR_TOKEN
# 12자 이상 새 시연용 비밀번호를 숨겨 두 번 입력합니다. 해시만 환경 변수에 저장합니다.
export AEGIS_LOGIN_PASSWORD_HASH="$(PYTHONPATH=src python -m aegis_on.auth_sessions hash-password)"
if [[ -n "$AEGIS_LOGIN_PASSWORD_HASH" ]]; then
  python -m uvicorn --app-dir src aegis_on.api:app --host 127.0.0.1 --port 8000
else
  print '비밀번호 설정 실패: 서버를 시작하지 않습니다.'
fi
```

비밀번호와 수집기 비밀은 화면 공유·셸 히스토리·저장소에 기록하지 마세요. `AEGIS_DEMO_DIR`은 이번 시연에만 사용되는 별도 경로이며, 인증 상관분석에 필요한 `.correlation-key`도 해당 임시 DB 옆에 생성됩니다. PII 모델은 비활성화되며 기존 정규식 가림만 적용합니다. 가명 정보에도 연결·추측 위험이 있습니다.

1. 브라우저에서 `http://127.0.0.1:8000/`에 접속해 `demo-analyst`와 방금 설정한 비밀번호로 로그인합니다.
2. 관제 개요 또는 **엔드포인트** 화면의 수집기 등록란에 `demo-collector`를 입력해 등록합니다. 발급된 비밀은 발급 화면을 닫기 전 복사할 수 있으며, 화면을 닫은 후 다시 볼 수 없습니다. 화면이 복사 실패를 알리면 지원되는 로컬 보안 컨텍스트에서 다시 시도하고, 비밀을 얻지 못한 상태로 닫았다면 해당 수집기를 폐기한 뒤 재발급합니다.
3. 서버를 실행한 터미널은 그대로 두고, **새 터미널**에서 저장소 루트로 이동합니다. 아래 명령에서 발급받은 수집기 비밀을 숨김 입력으로 붙여넣습니다. 비밀 자체를 명령줄 인수로 넣지 않습니다. 다음 `read` 문법은 macOS 기본 zsh용입니다.

```zsh
read -r -s 'AEGIS_COLLECTOR_TOKEN?수집기 인증 정보 붙여넣기: '
printf '\n'
export AEGIS_COLLECTOR_TOKEN
```

각 시나리오는 다음 명령을 하나씩 실행합니다. 전송기는 **127.0.0.1만** 사용하며 프록시와 리디렉션을 허용하지 않습니다. 입력 파일 경로, 외부 주소, 실제 로그를 받지 않습니다. 각 실행은 서로 다른 가상 호스트·레코드 ID와 배치 키를 사용합니다.

## 1. 정상 관리자 작업을 모사한 프로세스

```zsh
python scripts/presentation_scenarios.py normal --collector-id demo-collector
```

가상 Sysmon ID 1 하나에 `whoami /groups`라는 **문자열**을 넣어 전송합니다. 이 문자열은 실행하지 않습니다. **수집 이벤트**에서 `Sysmon 1 · 프로세스`, 발생·수신 시각과 호스트 가명, 관련 경고를 확인합니다. 제공된 기본 규칙·키워드 기준선과 비활성 공격 모델로 독립 테스트했을 때 이 사례는 경고가 없었지만, 설정이나 모델·규칙이 다르면 결과가 달라질 수 있습니다. 정상 작업도 오탐될 수 있으므로 '안전 판정'이라고 설명하지 않습니다. 이 사례는 경고를 인위적으로 만들기 위한 것이 아닙니다.

발표 예: “관리 명령을 모사한 이벤트가 수집됐고, 기록된 정보와 관련 경고 유무를 분석가가 확인합니다.”

## 2. 인증 실패 후 성공

```zsh
python scripts/presentation_scenarios.py auth --collector-id demo-collector
```

가상의 인증 실패 3건과 그보다 늦은 성공 1건을 **두 배치**로 전송합니다. 같은 수집기·보고 호스트·가상 계정·출발지 기준 10분 내 실패 후 성공이므로 **탐지 결과**에서 `Repeated authentication failures followed by success`의 **상관분석** 결과가 예상됩니다. 상세를 열어 관련 인증 이벤트 4건, 발생·수신 시각, 관찰 기간과 근거를 확인합니다. 수집 이벤트 화면에서는 `인증 실패`와 `인증 성공`을 구분합니다. 이 데이터는 실제 로그인이나 로그인 성공 확인이 아닙니다.

발표 예: “실패가 반복된 다음 성공했다는 로그 패턴을 검토 대상으로 표시했습니다. 공용 주소, 실수 또는 승인된 점검일 수 있으므로 실제 침입은 분석가가 추가 확인해야 합니다.”

## 3. Sysmon 다수 목적지 연결

```zsh
python scripts/presentation_scenarios.py fanout --collector-id demo-collector
```

한 가상 수집기·호스트에서 서로 다른 문서화용 목적지(`198.51.100.1`~`.3`)로 향하는 발신 Sysmon ID 3 이벤트를 **세 배치**로 전송합니다. 실제 네트워크 연결은 하지 않습니다. 10분 내 세 목적지 조건으로 **탐지 결과**에서 `Potential multiple-destination connections`, `상관분석`이 예상됩니다. 상세에서 관련 이벤트 3건과 기간·목적지 개수 근거를 확인합니다. 이 경고는 같은 프로세스, 실제 장치 또는 스캔·공격이 확인됐다는 의미가 아닙니다. 정상 모니터링도 조건을 충족할 수 있습니다.

발표 예: “여러 목적지 연결이라는 관찰 조건을 상관분석했습니다. 근거를 보고 정상 모니터링인지 추가 조사할지 결정합니다.”

## 근거 확인과 승인 시뮬레이션

1. **탐지 결과**에서 인증 또는 팬아웃 경고를 선택합니다. 표시되는 발생 시각과 서버 수신 시각, 출처, 관련 이벤트 ID, 근거와 `pending_review` 상태를 확인합니다.
2. `시뮬레이션 승인`을 눌러 `demo review` 같은 가상의 사유를 입력합니다. 비밀·개인정보는 입력하지 않습니다. 화면은 실제 차단을 수행하지 않습니다.
3. **분석 이력**에서 승인 시뮬레이션 이력을 확인합니다. 서버를 같은 임시 DB로 재시작하면 보존됩니다. 관련 경고가 여러 개라면 발생 시각과 근거를 보고 대상 경고를 확인합니다.
4. 실제 Windows 로그 수집, 실환경 웹·방화벽 수집, 인증→Sysmon 교차 사건 연결, AI의 실환경 성능은 이 시연에서 입증하지 않습니다. 테스트 주소만 포함한 합성 입력이라는 사실을 발표에 밝혀주세요.

## 예상 결과가 안 나올 때

- 전송기가 `HTTP 401`을 반환하면 올바른 수집기 ID와 발급된 비밀인지, 인증이 폐기되지 않았는지 확인합니다. 비밀을 채팅이나 로그에 붙이지 마세요.
- `HTTP 409`는 ID·배치 내용 충돌입니다. 새 실행은 새 ID를 만들지만, 응답이 유실된 뒤 **다시 실행하면 새 관찰을 추가**할 수 있습니다. 이미 저장된 이력을 먼저 확인하세요.
- `HTTP 503`은 저장소·인증 상관 키 또는 처리 제한을 확인해야 합니다. 임시 DB와 `.correlation-key`를 유지하고 서버 로그의 일반 오류만 확인하세요.
- 경고가 안 보이면 전송 완료 여부, 분석 이력과 이벤트 시각·출처를 확인하고 탐지 결과에서 새로고침합니다. 각 출력은 **배치 수신 확인**이며 탐지가 반드시 생성됐다는 뜻은 아닙니다.
- 대시보드 자동 갱신은 열린 상세나 사용자 작업 중 일시 중지될 수 있습니다. 상세를 닫거나 수동 새로고침하세요. 수집기 목록은 마지막 보고이며 PC의 온라인 여부를 뜻하지 않습니다.

## 종료와 다시 시작

서버 터미널에서 `Ctrl-C`로 종료하고 전송기 터미널에서 `unset AEGIS_COLLECTOR_TOKEN`을 실행합니다. 터미널을 닫아 환경 변수도 지웁니다. **기존 DB를 삭제하거나 초기화하는 명령은 실행하지 않습니다.**

처음부터 다시 시연하려면 서버를 종료한 뒤 위 준비 절차에서 새 `mktemp` 임시 폴더를 만들고 `AEGIS_HISTORY_DB`와 `AEGIS_AUTH_DB`를 새 경로로 설정해 재시작합니다. 새 시연 DB에서는 수집기를 다시 등록·발급해야 합니다. 이전 임시 폴더를 나중에 정리할 때는 먼저 실제 시연 폴더가 맞는지 경로와 내용을 직접 확인하세요. 운영 또는 다른 작업의 DB·키는 건드리지 마세요.
