# CodeBERT 검토 순위

Sysmon Event ID 1의 명령줄에서 추가 조사 가능성을 추정한다. 관제 화면은 기존 위험 점수와 승인 기능을 그대로 사용하며 CodeBERT가 제안한 순위를 함께 표시한다. 보호 대상은 승인 필요 경보와 점수 70점 이상의 규칙 경보다.

## 입력

- `events.jsonl`의 각 행은 `case_id`, `source_ref`, `scenario_id`, `run_id`, Sysmon `System`과 `EventData`를 담는다. 원본 내보내기의 실행 단위와 이벤트 순서를 보존한다.
- `labels.jsonl`의 각 행은 같은 `case_id`, `label`(`benign`, `review`, `unknown`), 판정 근거의 `evidence_ref`, 유사 명령을 묶는 `command_family`, 실제 조사 건을 묶는 `investigation_id`를 담는다. 참조값에는 내부에서 승인된 식별자를 쓴다.
- 학습용 `base/`에 공식 CodeBERT 리비전 `46c25bcc277a0ddc06c66439b04d5b61d3638ea3`의 로컬 설정, 토크나이저, `model.safetensors`를 준비한다. 가중치 SHA-256은 `b3a59026bf4955d5dbfae2ec74734b2d38c01049a84df1e8a12d78d0fd11bd75`다.
- 전처리는 일반적인 비밀 옵션 값과 경로 내 사용자명, 이벤트의 계정·호스트 식별자, 이메일, 전화번호, IP, GUID를 가린다. 조직별 식별자와 비정형 비밀이 섞인 원본 로그는 승인된 환경에서 처리한다.

## 학습과 평가

아이디어톤 합성 로그로 진행한 추가 학습과 AP 비교는 [CodeBERT AP 개선 실험](codebert_ap_improvement.md)에 정리했다.

저장소 루트에서 학습용 Python 환경에 `requirements.txt`와 `requirements-codebert-train.txt`를 설치한다. 다음 경로는 로컬 작업 디렉터리를 예시로 사용한다. 출력 디렉터리는 매 실행에서 새 경로를 사용한다.

```sh
export PYTHONPATH=src
python -m aegis_on.codebert_data prepare --events run/events.jsonl --labels run/labels.jsonl \
  --base run/base --out run/splits
python -m aegis_on.codebert_data audit --splits run/splits
python -m aegis_on.codebert_train --base run/base --train run/splits/train.jsonl \
  --validation run/splits/validation.jsonl --out run/model
python -m aegis_on.codebert_evaluate candidates --events run/events.jsonl \
  --split-file run/splits/validation.jsonl --split validation --out run/validation-cards.json
python -m aegis_on.codebert_evaluate calibrate --validation run/splits/validation.jsonl \
  --candidates run/validation-cards.json --model run/model --out run/policy.json
python -m aegis_on.codebert_evaluate candidates --events run/events.jsonl \
  --split-file run/splits/test.jsonl --split test --out run/test-cards.json
python -m aegis_on.codebert_evaluate evaluate --test run/splits/test.jsonl \
  --candidates run/test-cards.json --model run/model --policy run/policy.json --out run/evaluation.json
python -m aegis_on.codebert_export --model run/model --test run/splits/test.jsonl \
  --candidates run/test-cards.json --policy run/policy.json --evaluation run/evaluation.json --out run/onnx
```

분할은 시나리오, 실행, 명령 계열, 정규화 명령줄 또는 조사 건을 공유하는 모든 행을 함께 배정한다. `audit` 명령은 세 분할의 체크섬, 사례 ID 중복, 그룹 겹침, 사용 가능한 정상·조사 필요 라벨을 검사한다. 검사에 성공하면 분할별 행·그룹·라벨 수를 출력한다. 최종 평가 데이터는 학습이나 정책 보정에 사용하지 않는다. 출처와 분할 결과는 `source-audit.json`, `split-audit.json`에서 확인한다.

후보 생성은 기존 탐지 파이프라인을 실행한다. 담당자가 독립적으로 확인한 자산 중요도나, 자산·계정·시간이 일치하는 승인 작업 기록이 있다면 해당 카드의 `verified_critical_asset`, `approved_work_match`를 평가 전 설정할 수 있다. 운영 API의 맥락 점수는 이 정보의 제공원이 연결될 때까지 0이다. AI 점수가 없거나 모델 오류가 발생한 배치에서는 기존 순위를 반환한다.

`evaluation.json`은 4가지 방법의 상위 10개 카드가 포함한 조사 건, 빠진 조사 건, 오탐·미탐 및 점수 커버리지를 기록한다. `quantization.json`은 FP32와 INT8 파일 크기, CPU p50·p95, 새 미탐과 상위 10건의 변화, 선택 결과를 기록한다. INT8은 정수 연산과 크기 감소가 확인되고 새 미탐 없이 상위 10건과 보호 경보 순서 기준을 통과할 때 선택한다. 합성 데이터 실험은 성능 승격 판정에서 제외한다.

## 로컬 API 연결

런타임 환경에 `requirements.txt`와 `requirements-codebert-runtime.txt`를 설치한다. 운영자가 확인한 매니페스트 해시를 별도로 설정한 뒤 API 프로세스를 시작한다.

```sh
export AEGIS_CODEBERT_SHADOW_DIR="$PWD/run/onnx"
export AEGIS_CODEBERT_SHADOW_MANIFEST_SHA256='<verified-manifest-sha256>'
python -m uvicorn --app-dir src aegis_on.api:app --host 127.0.0.1
```

비활성화는 두 환경 변수를 제거하고 API 프로세스를 재시작한다. `--fixture`로 준비·학습한 패키지는 `AEGIS_CODEBERT_SHADOW_ALLOW_FIXTURE=1`로 로컬 검증할 수 있다. 응답과 이력은 보호된 모델 상태와 경보 순서, 점수, 가명처리된 이벤트 참조를 제공한다.
