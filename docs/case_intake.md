# 원천 로그 인계 확인

원본 사례 패키지와 프레임워크 인계 패키지를 접근이 제한된 경로에 준비한 뒤 저장소 루트에서 파일 목록을 만든다.

```bash
PYTHONPATH=src python -m aegis_on.case_intake_inventory \
  --original /private/path/original-package \
  --intake /private/path/intake-package > /private/path/case-intake-inventory.json
```

`--original`은 `manifest.json`과 `cases/`가 있는 디렉터리다. `--intake`는 `runtime_cases/`, `synthetic_cases/`와 인계 파일 4개가 있는 디렉터리다.

출력에는 패키지 기준 상대 경로, 파일 크기, SHA-256과 읽지 못한 항목이 담긴다. 필수 자료가 없거나 읽을 수 없으면 종료 코드 1을 반환한다. 인계자가 기록한 체크섬이 있으면 계산 결과와 대조한다. 출력의 파일명도 내부 정보를 담을 수 있어 원본과 같은 접근 제한을 적용한다.

`case_manifest.load_cases`는 #24 데모의 인계 규격 1.0을 읽는다. 패키지의 파일 목록과 `SHA256SUMS.txt`를 대조하고 두 manifest를 `case_id`로 연결한다. 증거 경로는 같은 사례 디렉터리에 있고 체크섬 검증을 통과해야 한다. 실제 관측은 `not_assigned`, 합성은 `synthetic_demo`로 처리한다. 보안팀의 라벨 검토 기록과 학습 사용 조건을 확인한 후 분할 대상을 선정한다.

## #25 원본 사례 검토 자료

PR #27의 두 패키지에서 인계 55개와 원본 26개 파일의 SHA-256을 대조했다. #24의 인계 목록 7건과 #25의 원본 manifest 3건은 `case_id`가 겹치지 않는다. 인계 패키지의 `frameworks/ARTEX.json`에서 원본 ARTEX 사례를 참조한다. 이 참조에는 학습 라벨이 없다.

| 원본 사례 | 관측 시각(UTC) | 확인한 근거 | 판정 보류 사유 |
| --- | --- | --- | --- |
| `CASE-ARTEX-20261121-01` | `2026-11-21T11:14:29Z` | 타임라인 4행과 웹 요청 4건 | 격리 Docker 웹 요청의 범위와 당시 Sysmon 수집 설정을 보안팀과 대조해야 한다. |
| `CASE-NORMAL-CANDIDATE-20261121-01` | `2026-11-21T09:49:11Z` | 타임라인 1행과 웹 요청 1건 | 승인 증빙이 보존되지 않아 작업의 승인 여부를 확인해야 한다. |
| `CASE-NORMAL-APPROVED-20261121-02` | `2026-11-21T16:47:44Z` | 타임라인 1행과 웹 요청 1건, 격리 서비스 상태 점검 승인 기록 | 승인 범위와 이벤트가 일치하는지 보안팀이 확인해야 한다. |

각 행의 근거는 `datasets/learning_eval_log_package_2026-11-21/cases/<case_id>/` 아래 `timeline.json`, `web_and_auth_logs.json`, `case_metadata.json`에 있다. 세 원본 라벨은 `unassigned`다. 세 사례의 `sysmon_event_1.json`과 `sysmon_event_3.json`은 모두 수집 이벤트가 0건이므로 이 자료에서 CodeBERT 학습용 명령줄을 만들 수 없다.
