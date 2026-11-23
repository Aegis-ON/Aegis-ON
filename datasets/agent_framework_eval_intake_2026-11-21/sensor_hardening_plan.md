# 센서 보강 계획

## 현재 확인한 공백

현재 Windows Sysmon 규칙은 `testCurl.exe`만 Process Create 및 Network Connect 대상으로 포함한다. 따라서 Docker 컨테이너 안에서 발생하는 ARTEX 또는 승인 상태 점검 웹 요청은 대상 웹 로그에 남아도 Windows Event ID 1·3에는 남지 않았다. 이 상황에서 빈 Sysmon 배열을 탐지 모델의 음성 근거로 쓰면 안 된다.

2026-11-21의 내부 Docker 검증도 이 공백을 재확인했다. 내부 브리지(`Internal=true`)에서 프로브 컨테이너가 합성 HTTP 대상에 `GET /`를 한 번 성공했지만, Windows Sysmon은 Docker Desktop Linux VM 안의 프로세스·네트워크 흐름을 직접 나타내지 않는다. 따라서 Windows Event ID 1·3, Docker lifecycle, 컨테이너 stdout/stderr, 대상 access log를 한 신호로 합치면 안 된다.

## 이번 검증에서 실제로 확보한 경계 신호

- `docker events`의 `create`, `start`, `die`는 컨테이너명·이미지·exit code를 제공했다. 생성과 종료, 실패 원인을 타임라인에 연결하는 데 사용한다.
- `docker inspect`는 `ReadonlyRootfs`, `CapDrop`, 메모리·PID 제한, 네트워크 `Internal`, 엔드포인트 정보를 제공했다. 공유본에서는 IP/MAC/컨테이너 ID를 안정 가명으로 치환한다.
- `docker top`은 실행 중 대상 컨테이너의 Python HTTP 서버 프로세스와 PID/PPID를 보여 주었다. Docker Desktop Linux VM의 PID이므로 Windows 호스트 PID와 동일시하지 않는다.
- 합성 대상의 stdout access log는 한 건의 `GET /`와 응답 200을 기록했다. 요청 출발지는 컨테이너 IP였으며 공유본에서는 `CONTAINER-CLIENT-01`로 바꿨다.
- PentAGI는 별도 내부 네트워크 컨테이너에서 시작했으며, 데이터베이스 DNS 미해결과 읽기 전용 파일시스템 오류가 stdout/stderr에 남았다. API·에이전트 태스크·외부 LLM 호출은 시작되지 않았다.
- CyberStrikeAI는 컨테이너 내부 루프백(`LOOPBACK-SVC-01:8080`)에만 바인드되어, 같은 Docker 내부망의 별도 컨테이너 이름 해석만으로는 접근할 수 없었다. 따라서 상태 점검은 동일 네트워크 네임스페이스에서 수행하고, 별도 클라이언트 컨테이너 실패를 서비스 장애로 잘못 라벨링하지 않는다.
- CyberStrikeAI 최종 수집에서는 Docker 이벤트의 생성·시작·종료와 logs·top·inspect를 확보했다. 컨테이너는 Pi 런타임 빌드 실패 후 이미 종료되어 있었으므로, 상태 점검을 위해 재기동하지 않았고 loopback 요청도 새로 만들지 않았다.
- Cairn의 후속 준비에서는 고정 커밋을 Docker 관리 Linux 볼륨에만 clone하고, 그 볼륨의 `cairn/uv.lock`에서만 허용된 미러 URL 치환을 적용했다. `uv sync --frozen`은 CPython 3.13용으로 잠긴 `watchfiles`, 승인된 CPython 3.12 재시도에서는 잠긴 `h11` 아티팩트의 PyPI 404에서 각각 실패했다. Python 3.12 sync 컨테이너의 `docker ps`·logs·top·inspect·events는 수집했지만, `cairn serve` 컨테이너 자체가 없으므로 runtime 프로세스 스냅샷과 내부 loopback health는 누락이 아니라 관측 객체 부재다. 이를 성공한 격리 런타임 증거로 승격하면 안 된다.
- Cairn CASE-02는 CASE-01과 별도 Docker 관리 volume의 runtime-copy tree에서 새 lockfile을 생성해 실제 `cairn serve`를 기동했다. `docker inspect`는 read-only rootfs·host bind 없음·호스트 포트 없음·cap-drop ALL·no-new-privileges·tmpfs·PID 128·메모리 1 GiB를, `docker network inspect`는 `Internal=true`를 확인했다. 서비스는 container loopback에서 listen했고, 같은 network namespace의 GET / 두 건을 200으로 기록했다. Alpine 클라이언트의 body 저장은 read-only rootfs로 막혔으므로, client-side capture 오류와 server-side 200을 함께 보존한다. 이 사례에도 dispatcher·worker·보안 도구·타깃·외부 LLM/API는 없으므로 행동 텔레메트리로 일반화하면 안 된다.
- HexStrike AI는 공식 GitHub advisory와 공식 releases index만 재검토했다. advisory의 affected/patched version은 모두 `Unknown`이고 release index는 비어 있어 공식 수정 커밋·릴리스·이미지 digest·Execute Endpoint 입력 경로의 수정 근거를 특정하지 못했다. 따라서 Docker/VM/프로세스/네트워크 관측값은 없으며, 그 부재를 런타임 실패나 정상 기동 증거로 해석해서는 안 된다.
- `CASE-HEXSTRIKE-GATE-20261122-01`은 HexStrike 관측 로그가 아닌 synthetic schema fixture다. 정책 거부 이벤트와 선언된 컨테이너 경계 모양은 parser·상관분석·대시보드 검증에만 쓰며, 실제 Docker/VM/프로세스/네트워크/MCP/웹 신호와 결합하거나 행동 텔레메트리로 일반화해서는 안 된다.
- `CASE-SYNTHETIC-CONFIRMED-INCIDENT-20261122-01`은 Sysmon Event ID 1·3, 웹/인증, 상관 경보 형식을 검증하는 비실행 관제 데모 fixture다. 고정 UTC·가명·동일 요청 ID로 신호 결합을 시험하지만, 실제 침해·프로세스·네트워크·인증·웹 활동이 아니다. `confirmed_security_incident`는 exercise label이고 관제 표시는 `simulated_confirmed_security_incident`로 제한한다.

## 다음 실험 전 최소 보강

1. **컨테이너 경계 기록** — Docker 이벤트와 컨테이너 ID, 이미지 다이제스트, 네트워크 이름, 시작·종료 UTC를 별도 JSONL로 기록한다. 원시 ID·이름은 공유 시 안정 가명으로 치환한다.
2. **전용 수집 래퍼** — Windows에서 실험을 시작하는 전용 래퍼만 Sysmon Event ID 1·3 포함 대상으로 두고, 도구명·커밋·시나리오 ID·대상 가명을 명령줄 메타데이터에 넣는다. 일반 사용자 PowerShell 전체를 수집 대상으로 넓히지 않는다.
3. **컨테이너 내부 관측** — 프레임워크 컨테이너에는 eBPF/auditd 또는 프로세스·네트워크 감사 수단을 추가한다. 이 기록을 Windows Sysmon의 대체물이 아니라 보완 자료로 취급한다.
4. **웹·인증 상관성** — 합성 서비스는 요청 ID, UTC, 출발지 가명, 경로, 상태, 인증 결과(해당 시)를 남긴다. 로그인 GET과 실제 인증 결과는 분리한다.
5. **egress 차단·기록** — 기본 거부 방화벽에서 `SERVICE-WEB-01`만 allow-list한다. 거부된 외부 접속 시도도 사례 타임라인에 기록한다.
6. **프로비넌스** — 커밋, 이미지 다이제스트, SBOM, 설정 해시, 모델 모드(local/mock)를 모든 사례 메타데이터의 필수 필드로 만든다.
7. **Docker Desktop 경계 한계 명시** — `docker top` PID는 Linux VM 관측값이고 Windows Sysmon Event ID 1·3과 직접 조인하지 않는다. 조인은 컨테이너 ID(공유본은 가명), 이미지 다이제스트, UTC 구간, 요청 ID로 한다.
8. **수집 명령 검증** — 실행 전 `docker network inspect`가 `Internal=true`인지 확인하고, 각 컨테이너의 `ReadonlyRootfs`, `CapDrop`, 마운트, 호스트 포트, `docker.sock` 미제공 여부를 사례 메타데이터에 기록한다.
9. **루프백 서비스 점검** — 프레임워크가 컨테이너 루프백에만 바인드되면 `--network container:<name>`의 단발성 읽기 전용 HTTP 점검 컨테이너로만 확인한다. 호스트 포트 게시나 일반 브리지 네트워크 노출로 우회하지 않는다.
10. **합성 fixture 경계** — `synthetic_cases/`의 레코드에는 `synthetic=true`, `framework_runtime_observed=false`, 적격성 제한과 고정 가명을 필수로 둔다. 이 레코드는 실제 런타임의 부재를 대신 증명하지 않으며, parser·상관분석·대시보드 검증 외 학습 데이터에 투입하지 않는다.
11. **합성 확정사고 표시** — 합성 관제 fixture에서 `confirmed_security_incident`를 사용할 때는 `not_actual_incident=true`, `eligible_for_production_validation=false`, `display_label=simulated_confirmed_security_incident`를 함께 요구한다. 실제 침해 통계와 실운영 탐지 성능 지표에서 이 fixture를 제외한다.

## 라벨 안전장치

- 도구 이름만으로 공격 라벨을 붙이지 않는다.
- 승인된 정상도 웹 로그·프로세스·컨테이너 수명주기 중 하나 이상이 누락되면 `telemetry_incomplete`로 표시한다.
- 보안팀이 원본 타임라인과 승인 기록을 비교해 최종 라벨을 붙인다.
