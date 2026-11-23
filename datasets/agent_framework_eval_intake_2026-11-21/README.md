# Aegis-ON 에이전트형 보안 도구 학습·평가 수집 인테이크

이 묶음은 ARTEX, CyberStrikeAI, Cairn, PentAGI, HexStrike AI를 동일한 방식으로 수집·평가하기 위한 안전한 인테이크 패키지다. 공개 설명·실제 관측·실패한 실행 시도·합성 schema fixture를 섞지 않으며, 실제 관측은 `runtime_cases/`, 비적격 시도는 `attempts/`, 합성 fixture는 `synthetic_cases/`에 분리한다.

## 범위와 상태

| 프레임워크 | 공식 또는 확인된 출처 | 실행 상태 | Aegis-ON 취급 |
| --- | --- | --- | --- |
| ARTEX | 원 제작자의 공개 저장소가 철회된 상태 | 기존 격리 사례만 보유 | 신규 fork·이미지는 자동 실행 금지 |
| CyberStrikeAI | `AIPentest/CyberStrikeAI` | 내부망·루프백 전용 실제 기동 후 로컬 Pi 런타임 빌드 실패로 자율 종료, 최종 수명주기 수집 완료 | 시작·실패 수명주기 텔레메트리 전용; 행동 라벨 금지 |
| Cairn | `oritera/Cairn` | CASE-01 실패 증거를 보존하고, CASE-02의 별도 Docker 관리 런타임 복제본에서 새 lockfile을 생성해 내부망 loopback `cairn serve`를 실제 기동·수집·안전 중지 | 시작·수명주기·loopback health 텔레메트리 전용; 행동 라벨 금지 |
| PentAGI | `vxcontrol/pentagi` | 내부망 단일 컨테이너 실제 기동, DB 미연결로 종료 | Docker socket·호스트 포트·외부 egress 없이 실행 |
| HexStrike AI | `0x4m4/hexstrike-ai` | 차단·미실행 | 2026-11-22 공식 GHSA 검토에서 patched version이 `Unknown`이고 공식 릴리스도 없어, 수정 commit/release·이미지 digest·입력 경로 코드 변경 근거를 확정하지 못함 |

## 이 묶음이 하는 일과 하지 않는 일

- 하는 일: 도구 식별·버전 고정·컨테이너 수명주기·프로세스·네트워크·웹/인증 로그의 공통 스키마와 수집 전제조건을 제공한다.
- 하지 않는 일: 공개 저장소의 최신 코드를 자동으로 신뢰하거나, 인터넷 대상·취약점 악용·인증 우회·외부 LLM 서비스 호출을 실행하지 않는다.
- 실제 사례를 만들 때는 `scenario_matrix.json`의 `allowed` 행만 사용하고, 수집 파일에 이미지 다이제스트와 커밋을 추가한다.
- `runtime_cases/CASE-PENTAGI-STARTUP-20261122-01`은 실제 기동 사례다. 데이터베이스 미연결과 읽기 전용 파일시스템으로 안전하게 중단됐으며, 공격·정찰·인증·외부 LLM 호출은 실행하지 않았다.
- `runtime_cases/CASE-CYBERSTRIKEAI-STARTUP-20261122-01`은 Linux Docker-managed 볼륨에서 컴파일 후 내부망 컨테이너로 실제 기동된 사례다. 서비스는 컨테이너 루프백에만 바인드됐고, 이후 Pi 런타임 빌드 실패로 자율 종료했다. Docker logs·top·inspect·events로 최종 수명주기를 수집했으며, 이미 종료된 서비스를 재기동하지 않아 loopback health는 의도적으로 생략했다.
- `runtime_cases/CASE-CAIRN-SERVE-20261122-01`은 고정 커밋을 Docker 관리 Linux 볼륨에만 clone한 실제 격리 준비 사례다. 이 볼륨 안에서만 lockfile 인덱스를 `pypi.org`로 치환하고 전·후 SHA-256을 기록했다. `uv sync --frozen`은 공식 CPython 3.13 이미지에서 잠긴 `watchfiles` wheel, 승인된 CPython 3.12 재시도에서 잠긴 `h11` wheel의 PyPI 404로 각각 멈췄다. `cairn serve`, worker, dispatcher, 보안 도구, 대상 접근, 외부 LLM/API 호출, 호스트 포트, Docker socket은 없었으며 sync 컨테이너와 볼륨은 보존했다.
- `runtime_cases/CASE-CAIRN-SERVE-20261122-02`는 CASE-01을 덮어쓰지 않고 별도 Docker 관리 Linux runtime volume에서 만든 실제 격리 기동 사례다. 기존 lockfile과 새 lockfile을 분리 보존하고 각각 SHA-256을 기록했다. 새 lock은 고정 커밋의 변경하지 않은 `pyproject.toml`에서 일회성 PyPI 기본 인덱스 옵션으로 재생성했다. `cairn serve`는 internal Docker network·read-only rootfs·tmpfs·cap-drop ALL·no-new-privileges·PID/메모리 제한으로 기동되어 컨테이너 loopback에만 listen했다. 서버 로그는 같은 network namespace의 GET / 두 건에 HTTP 200을 기록했고, 이후 `docker stop`으로 exit code 0의 정상 종료를 확인했다. dispatcher, worker, 보안 도구, 대상 접근, 외부 LLM/API, 호스트 포트, Docker socket은 없었다.
- `runtime_cases/CASE-DOCKER-BOUNDARY-20261122-01`은 내부 Docker 네트워크의 정상 비교 사례다. 제한된 프로브가 합성 HTTP 서비스에 `GET /` 한 번을 수행했다.
- `attempts/`에는 초기 격리 빌드 결과와 HexStrike의 비실행 게이트 검토가 보존된다. CyberStrikeAI의 초기 실패는 Windows 공유 파일시스템의 파일명 제약으로 판명됐고, 후속 실제 기동 사례와 구분한다. Cairn의 초기 시도는 잠금 의존성 미러 DNS 문제였고, CASE-01 Docker 관리 볼륨 시도는 PyPI에 없는 CPython 3.13 `watchfiles`와 CPython 3.12 `h11` 잠금 wheel에서 각각 실패했다. `HexStrikeAI_gate_review_20261122.json`은 공식 advisory의 patched version `Unknown`과 공식 release 부재를 기록한 차단 사례이며, clone·image pull·VM 생성·컨테이너 생성·실행은 없었다. 이 실패·차단 사례에 모델 학습/평가용 행동 라벨을 붙이면 안 된다.
- `synthetic_cases/CASE-HEXSTRIKE-GATE-20261122-01`은 GHSA-crrg-2r24-3g67의 수정본 미확인 게이트를 표현한 정적 schema fixture다. 실제 HexStrike 런타임·실행·네트워크·프로세스·MCP 호출·웹 요청은 없으며, 파서·상관분석·대시보드 검증에만 사용할 수 있다. 프레임워크 학습, 행동 평가, 공격 라벨에는 부적격이다.
- `synthetic_cases/CASE-SYNTHETIC-CONFIRMED-INCIDENT-20261122-01`은 합성 Sysmon·웹/인증·상관 경보를 묶은 관제 데모 fixture다. `confirmed_security_incident`는 상관·우선순위 표시용 exercise label이고, 표시는 반드시 `simulated_confirmed_security_incident`로 한다. 실제 침해·실행·네트워크·인증·웹 관측이 아니며, 실운영 성능, 침해 통계, 실제 학습 정답에는 사용할 수 없다.

## Aegis-ON 관제 분류 체계

- `normal_approved`: 승인된 정상 작업의 실제 관측 후보
- `normal_authorized_runtime`: 승인된 제한 런타임과 상태 점검의 실제 관측; 보안팀 검토 전 학습·실운영 검증에는 사용하지 않음
- `operational_anomaly`: 운영 이상 신호로 추가 검토가 필요한 상태
- `policy_blocked`: 정책이 실행 전 차단한 상태
- `needs_investigation`: 관제사 조사가 필요한 미확정 신호
- `confirmed_security_incident`: 실제 침해 확정에만 쓰는 최종 분류이며, 합성 exercise에서는 표시값과 함께만 사용
- `synthetic_training_only`: 합성 fixture임을 나타내며 실제 학습 정답·실운영 검증에는 부적격

## AI 담당 인계 계약

`label_manifest.jsonl`은 모든 `runtime_cases/` 및 `synthetic_cases/`를 사례 단위로 한 번씩 열거하는 라벨 기준 파일이다. `training_split_manifest.jsonl`은 같은 `case_id`의 이벤트가 split을 넘지 않도록 통제한다. 현재 실제 사례는 보안팀 검토 또는 텔레메트리 전용 경계 때문에 모두 `not_assigned`이며, 합성 사례만 `synthetic_demo`로 분리된다. 따라서 이 패키지는 parser·정규화·상관분석·대시보드 작업에는 즉시 사용할 수 있지만, 지도학습 성능 평가에는 `insufficient_for_supervised_model_evaluation` 상태다. 상세 규칙은 [`labeling_guideline.md`](labeling_guideline.md)와 [`training_data_contract.json`](training_data_contract.json)을 따른다.

## 다음 동적 실행 전에 필요한 보강

1. 독립된 폐기 가능 VM 또는 격리 Linux 호스트에서만 실행한다. 현 사용 중인 Windows 데스크톱에는 새 프레임워크를 설치하지 않는다.
2. Docker/컨테이너 이벤트, 컨테이너 내부 프로세스·네트워크, 대상 웹 접근 로그를 UTC와 요청 ID로 함께 수집한다.
3. 현재 Windows Sysmon 규칙이 `testCurl.exe`만 포함하는 문제를 해결한다. 최소한 전용 수집 래퍼와 Docker CLI·백엔드 이벤트가 상관분석 가능해야 한다.
4. 기본 egress 차단, 대상은 `SERVICE-WEB-01`만 허용, 자격증명·클라우드 메타데이터·호스트 Docker socket은 프레임워크 컨테이너에 제공하지 않는다.
5. 이미지, SBOM, 커밋, 설정 파일 해시를 사례 메타데이터에 기록하고 토큰·비밀번호는 수집 전 제거한다.

실행 전 세부 사항은 [`frameworks/`](frameworks), 실제 관측은 [`runtime_cases/`](runtime_cases), 비적격 시도와 HexStrike 차단 근거는 [`attempts/`](attempts), 합성 parser·관제 데모 fixture는 [`synthetic_cases/`](synthetic_cases), AI 인계 기준은 [`label_manifest.jsonl`](label_manifest.jsonl)·[`training_split_manifest.jsonl`](training_split_manifest.jsonl)·[`labeling_guideline.md`](labeling_guideline.md)·[`training_data_contract.json`](training_data_contract.json), 수집 절차는 [`collection/docker_boundary_collection.ps1`](collection/docker_boundary_collection.ps1), 정규화 스키마는 [`collection/docker_boundary_schema.json`](collection/docker_boundary_schema.json), 현재 적격성은 [`VALIDATION_STATUS.md`](VALIDATION_STATUS.md), 시나리오는 [`scenario_matrix.json`](scenario_matrix.json), 센서 보강은 [`sensor_hardening_plan.md`](sensor_hardening_plan.md)에 있다.
