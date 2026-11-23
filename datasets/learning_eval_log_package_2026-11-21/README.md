# Aegis-ON 학습·평가용 로그 패키지

공유용으로 가명처리한, 격리 실습 환경의 세 개 관측 사례 묶음이다. 이 패키지는 탐지 모델의 정답지를 제공하지 않는다. 최종 라벨은 AI 담당과 보안팀이 실행 타임라인 및 승인 기록을 대조한 뒤에만 공동으로 확정해야 한다.

| 묶음 | 관측 구분 | UTC 구간 | 포함 자료 | 라벨 상태 |
| --- | --- | --- | --- | --- |
| `CASE-ARTEX-20261121-01` | 통제된 ARTEX 계열 실습 트래픽 | 2026-11-21T11:14:29.857991Z–2026-11-21T11:14:29.883902Z | 웹 접근 4건, 실행·범위 타임라인 | 미지정 |
| `CASE-NORMAL-CANDIDATE-20261121-01` | 기준선 `/health` 요청 | 2026-11-21T09:49:11.013041Z | 웹 접근 1건, 타임라인 | 미지정; 정상 **후보**이고 승인 증빙 미확보 |
| `CASE-NORMAL-APPROVED-20261121-02` | 승인된 격리 서비스 상태 점검 | 2026-11-21T16:47:44.139028Z | 웹 접근 1건, 실행 타임라인, Sysmon 조회 | 미지정; 승인된 정상 비교 **후보** |

## 핵심 제한

- 세 사례 모두 서비스 측 웹 로그로 관측된 **web-only** 사례다. 이후 Windows 원본 `Microsoft-Windows-Sysmon/Operational`을 각 5분 분석 구간으로 직접 조회했으며 각 사례의 Event ID 1·3은 각각 0건이었다. 빈 배열은 원시 Sysmon 이벤트가 없어서가 아니라, 해당 구간의 조회 결과가 0건이기 때문이다.
- `sysmon_event_1.json` 및 `sysmon_event_3.json`에는 조회 시각·범위·결과 수를 함께 기록했다. 단, 이 결과는 Windows Sysmon 규칙이 당시 `testCurl.exe`만 포함하고, ARTEX 요청은 별도 Docker 컨테이너에서 발생한 구성과 함께 해석해야 한다.
- `CASE-NORMAL-CANDIDATE-20261121-01`의 `/health`는 모니터링 용도로 보이는 기준선 요청이지만, 승인 티켓·운영자 기록은 보존되어 있지 않다. 반면 `CASE-NORMAL-APPROVED-20261121-02`는 이 수집 작업에서 명시적으로 승인한, 격리 서비스의 상태 점검이다. 두 사례와 ARTEX 사례 모두 최종 AI 라벨은 AI 담당과 보안팀의 타임라인 대조 전까지 미지정이다.
- 서비스는 인증 결과를 별도로 남기지 않았다. `/login`은 GET 접근 기록만 있으며 인증 성공·실패를 의미하지 않는다.

## 가명처리

실제 호스트명·IP·컨테이너명·원래 요청 ID는 공유본에 넣지 않았다. 같은 실체는 모든 파일에서 같은 값으로 치환했다.

- Windows 수집 대상: `HOST-WIN-01`
- 가상 웹 서비스: `SERVICE-WEB-01`
- ARTEX 실습 출발지: `SRC-ARTEX-01`
- 기준선 출발지: `SRC-MON-01`
- 승인 상태점검 출발지: `SRC-MON-APPROVED-01`
- 요청 ID: `REQ-ARTEX-*`, `REQ-NORMAL-*`, `REQ-NORMAL-APPROVED-*`

세부 규칙은 [`redaction_policy.json`](redaction_policy.json)에 있다. 토큰·비밀번호·원시 주소는 포함하지 않았다.

## 구성

```text
cases/
  CASE-ARTEX-20261121-01/
    case_metadata.json
    timeline.json
    web_and_auth_logs.json
    sysmon_event_1.json
    sysmon_event_3.json
    evidence_memo.md
  CASE-NORMAL-CANDIDATE-20261121-01/
    case_metadata.json
    timeline.json
    web_and_auth_logs.json
    sysmon_event_1.json
    sysmon_event_3.json
    evidence_memo.md
  CASE-NORMAL-APPROVED-20261121-02/
    case_metadata.json
    timeline.json
    web_and_auth_logs.json
    sysmon_event_1.json
    sysmon_event_3.json
    evidence_memo.md
validation/
  windows_direct_model_validation.json
  sysmon_reboot_validation.json
  pr_23_merge_validation.json
collection/
  export_sysmon_case.ps1
manifest.json
redaction_policy.json
SHA256SUMS.txt
```

`collection/export_sysmon_case.ps1`는 보강 수집용 읽기 전용 PowerShell 내보내기 스크립트다. 현재 결과는 직접 조회한 0건 결과이며, 새 실습을 추가할 때는 이 스크립트로 원본 이벤트와 사례 UTC 구간·호스트 가명 매핑을 함께 보존해야 한다.

현재 재검증 결과는 [`VALIDATION_STATUS.md`](VALIDATION_STATUS.md)에, Windows 직접 모델 추론·재부팅 뒤 Sysmon 자동 시작·PR 병합 근거는 [`validation/`](validation)에 정리했다.
