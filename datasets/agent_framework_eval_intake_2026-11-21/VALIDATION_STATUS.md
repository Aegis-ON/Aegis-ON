# 런타임 검증 상태 — 2026-11-22 KST

| 항목 | 상태 | 학습·평가 적격성 |
| --- | --- | --- |
| Docker 내부망 정상 비교 | 실제 실행·수집 완료 | 보안팀 타임라인 검토 후 정상 비교 후보 |
| PentAGI 기동 | 실제 실행·수집 완료, 내부 DB 미연결로 종료 | 텔레메트리 검증 전용; 행동/공격 라벨 금지 |
| CyberStrikeAI | 내부 Docker망·컨테이너 루프백에서 실제 기동 후, Pi 런타임 빌드 실패로 자율 종료한 최종 수명주기 수집 완료 | 시작·로컬 실패 수명주기 텔레메트리 전용; 행동 사례 부적격 |
| Cairn | CASE-01의 고정 lock 실패는 보존했다. CASE-02에서는 별도 Docker 관리 런타임 복제본에서 새 lockfile을 재생성하고 제한된 `cairn serve`를 실제 기동했다. 컨테이너 loopback의 GET / 두 건이 200으로 로그에 기록됐고, `docker stop` 뒤 exit code 0으로 종료했다. | 시작·수명주기·loopback health 텔레메트리 전용; worker/dispatcher·행동·공격 라벨 금지 |
| HexStrike AI | 2026-11-22 공식 GHSA 검토에서 patched version `Unknown`, 공식 릴리스 없음, fixed commit/release·image digest·입력 경로 코드 변경 근거 미확정 | 차단 — clone·image pull·폐기 가능 VM·컨테이너를 생성하거나 실행하지 않음 |
| HexStrike synthetic fixture | `CASE-HEXSTRIKE-GATE-20261122-01`은 수정본 미확인 게이트를 표현한 정적 schema fixture이며 실제 런타임 관측은 없음 | parser·상관분석·대시보드 검증 전용; 프레임워크 학습·행동 평가·공격 라벨 금지 |
| Synthetic confirmed-incident fixture | `CASE-SYNTHETIC-CONFIRMED-INCIDENT-20261122-01`은 Sysmon·웹/인증·상관 경보를 결합한 비실행 관제 데모 fixture이며 실제 침해 관측은 없음 | 관제 화면·상관분석·경보 우선순위 데모 전용; 실운영 검증·침해 통계·실제 학습 정답에 부적격 |

## 보존·중지 상태

- 단순 합성 HTTP 대상은 수집 뒤 의도적으로 중지했다. 삭제하지 않았다.
- PentAGI·프로브 컨테이너와 Cairn Docker 관리 볼륨도 삭제하지 않았다. Cairn CASE-01의 일회성 sync 컨테이너는 code 1로 종료됐고, CASE-02의 새 런타임 볼륨·lock/sync·health·runtime 컨테이너도 모두 보존했다. CASE-02 runtime은 명시적 `docker stop` 뒤 exit code 0으로 종료했다.
- CyberStrikeAI 컨테이너는 최종 수집 시 이미 `exited`였다. Docker 이벤트가 생성·시작·exit code 1 종료를 기록했고, `docker top`은 실행 중 프로세스가 없음을 반환했다. 재기동·health 요청·삭제는 하지 않았으며, 중지된 컨테이너와 Docker 볼륨을 보존했다.
- HexStrike AI는 실행하지 않았다. 공식 GitHub advisory GHSA-crrg-2r24-3g67의 patched version이 `Unknown`이고 공식 저장소의 release index에 릴리스가 없어, 공식 fixed commit/release·이미지 digest·Execute Endpoint 입력 경로의 코드 변경을 확인하지 못했다. 이 증거가 모두 마련되고 독립 폐기 VM이 별도로 준비된 뒤에만 다음 단계로 진행한다.
- `synthetic_cases/CASE-HEXSTRIKE-GATE-20261122-01`은 실행 사례가 아니다. 고정 UTC·가명·정책 거부 메타데이터만 가진 synthetic schema fixture이며, 실제 Docker/VM/컨테이너/네트워크/프로세스/MCP/웹 관측값이 없다.
- `synthetic_cases/CASE-SYNTHETIC-CONFIRMED-INCIDENT-20261122-01`은 실제 침해 사례가 아니다. `confirmed_security_incident`는 exercise correlation label이며, `simulated_confirmed_security_incident`로만 표시한다. 실제 Sysmon·네트워크·인증·웹 로그 또는 프레임워크 런타임 증거가 없으므로 실운영 검증과 실제 학습 정답으로 사용하면 안 된다.

## 라벨 경계

`CASE-PENTAGI-STARTUP-20261122-01`에는 프레임워크의 시작 및 의존성 거부만 있다. 타깃 접근, API 사용, 인증, 도구 실행, 취약점 검증, 외부 LLM 호출은 없었다. 따라서 이 사례에 공격/악성 라벨을 미리 부여해서는 안 된다.

`CASE-CYBERSTRIKEAI-STARTUP-20261122-01`에는 기동 배너·루프백 리스너·프로세스 격리 준비와 로컬 Pi 런타임 빌드 실패·종료 수명주기가 있다. 프레임워크 작업, 대상 접근, 보안 도구, MCP 도구, 외부 LLM/API 호출은 실행되지 않았다. 따라서 이 사례에도 행동/공격 라벨을 붙이면 안 된다.

`CASE-CAIRN-SERVE-20261122-01`에는 Docker 관리 볼륨의 고정 소스, lockfile 전·후 SHA-256, CPython 3.13 및 3.12 동기화 실패가 있다. Python 3.12 재시도에는 `docker ps`·logs·top·inspect·events가 수집됐고 exit code 1이 확인됐다. 두 재시도 모두 `cairn serve` 컨테이너를 생성하지 못했으므로 내부망·읽기 전용 rootfs·tmpfs·capability drop·no-new-privileges·런타임 프로세스·런타임 inspect/events·loopback health를 관측했다고 주장해서는 안 된다. 이 사례는 런타임 또는 행동 학습·평가에 사용하면 안 된다.

`CASE-CAIRN-SERVE-20261122-02`에는 별도 Docker 관리 런타임 볼륨, 분리 보존한 원본·신규 lock SHA-256, 내부망·read-only rootfs·tmpfs·cap-drop ALL·no-new-privileges·PID/메모리 제한의 실제 `cairn serve` 기동·프로세스·inspect/events와 종료 수명주기가 있다. 같은 network namespace의 읽기 전용 GET 두 건은 서비스 로그에서 HTTP 200으로 확인됐지만 Alpine 클라이언트는 read-only rootfs에 기본 출력 파일을 만들지 못했다. 이는 server-side health 성공 및 client-side body-capture 한계를 함께 나타내는 관측값이다. dispatcher·worker·보안 도구·타깃·외부 LLM/API는 실행하지 않았으므로 행동/공격 라벨을 붙이면 안 된다.

`CASE-HEXSTRIKE-GATE-20261122-01`은 synthetic schema fixture다. `policy_gate_denied_before_execution`과 `request_blocked_by_policy`는 parser·상관분석용으로 만든 정적 이벤트이며, 실제 Execute Endpoint 요청이나 HexStrike MCP 호출을 뜻하지 않는다. 따라서 프레임워크 학습·행동 평가·공격 라벨에 사용해서는 안 된다.

`CASE-SYNTHETIC-CONFIRMED-INCIDENT-20261122-01`은 synthetic exercise scenario다. Sysmon Event ID 1·3, 웹/인증, high severity 상관 경보 신호는 모두 비실행 메타데이터다. 관제사 판정도 `simulated_confirmed_security_incident`이며 실제 침해 확정이나 실운영 탐지 성능을 의미하지 않는다.

## AI 인계와 split 상태

`label_manifest.jsonl`과 `training_split_manifest.jsonl`은 모든 실제·합성 사례를 각각 한 번씩 포함한다. 현재 실제 행은 보안팀 검토 또는 텔레메트리 전용 경계로 `eligible_for_training=no`, `split=not_assigned`이고, 합성 행은 `eligible_for_training=synthetic_only`, `split=synthetic_demo`다. 따라서 지도학습 train/validation/test와 성능 수치는 만들지 않으며 상태는 `insufficient_for_supervised_model_evaluation`이다. `CASE-SYNTHETIC-CONFIRMED-INCIDENT-20261122-01`의 `confirmed_security_incident`는 반드시 `simulated_confirmed_security_incident` 표시와 함께만 사용한다.
