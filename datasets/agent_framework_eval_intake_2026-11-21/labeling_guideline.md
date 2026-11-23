# Aegis-ON 라벨링 가이드

## 목적과 우선순위

`label_manifest.jsonl`은 AI 담당이 사례 단위의 출처, 라벨, 신뢰도, 적격성, 증거 경로를 한 번에 읽는 기준 파일이다. 관제 우선순위 제안은 가능하지만, 이 패키지는 실제 침해 통계나 실운영 탐지 성능을 증명하지 않는다.

## 라벨 정의와 관제사 처리

| 라벨 | 의미 | 관제사 처리 |
| --- | --- | --- |
| `normal_approved` | 실제 통제된 정상 비교의 후보 | 타임라인 검토 뒤 정상 기준선으로만 승격 |
| `normal_authorized_runtime` | 실제 승인·제한된 런타임/상태 점검 | 범위 준수와 수명주기 텔레메트리를 확인 |
| `operational_anomaly` | 실제 초기화·의존성·로컬 런타임 실패 | 운영 원인을 분리해 조사하며 공격으로 승격하지 않음 |
| `policy_blocked` | 정책이 실행 전에 막은 조건 | 차단 근거와 요청 전 중지를 확인 |
| `needs_investigation` | 근거가 불충분한 실제 신호 | 보안팀 검토 전 결론·학습 라벨을 보류 |
| `confirmed_security_incident` | 실제 침해 확정용 최종 분류 | 실제 증거·보안팀 승인 없이는 사용 금지 |
| `synthetic_training_only` | 합성 fixture의 사용 경계 | parser·상관분석·대시보드 검증으로만 제한 |

## 실제·합성·차단의 경계

- `data_origin=actual_observed`는 이 패키지의 실제 수집 증거를 뜻하지만, `eligible_for_training=no` 또는 `label_status=pending_security_review`면 모델 학습·실운영 검증에 투입하지 않는다.
- `data_origin=synthetic` 또는 `synthetic=true`는 실행·침해 관측이 아닌 정적 exercise/fixture다. synthetic 행은 `synthetic_demo` split 밖으로 이동할 수 없다.
- `policy_blocked`는 실행 전 정책 차단을 뜻하며, 공격 성공·침해·프레임워크 런타임 관측을 뜻하지 않는다.
- `CASE-SYNTHETIC-CONFIRMED-INCIDENT-20261122-01`만 `confirmed_security_incident`를 보유한다. 이 행은 반드시 `display_label=simulated_confirmed_security_incident`, `not_actual_incident=true`, `eligible_for_production_validation=false`와 함께 표시한다.

## AI 모델의 허용 범위

- 로그 정규화와 필드 매핑
- `normal_approved`, `normal_authorized_runtime`, `operational_anomaly`, `policy_blocked`의 보조 분류
- 동일 case 내 이벤트 상관분석과 관제 우선순위 제안

`normal_authorized_runtime` 출력은 승인된 제한 런타임/상태 점검을 뜻할 뿐, 현재 manifest의 `pending_security_review` 및 `eligible_for_training=no` 경계를 해제하지 않는다.

## AI 모델이 주장하면 안 되는 범위

- 실제 침해 통계
- 실운영 공격 탐지 성능
- 합성 사례만으로 계산한 공격 탐지 정확도
- synthetic `confirmed_security_incident`를 실제 침해로 해석한 결론

## 검토와 승격

보안팀이 원본 타임라인·승인 기록·증거 경로를 재검토한 뒤에만 실제 행의 `label_status`, `eligible_for_training`, `eligible_for_production_validation`, `eligible_for_security_incident_statistics`, `confidence`, `case_group`을 갱신한다. 실제 양성 사례가 추가되더라도 합성 split과 실제 train/validation/test split을 결합하지 않는다.
