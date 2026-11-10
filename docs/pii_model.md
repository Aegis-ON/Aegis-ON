# 로컬 PII NER

개인정보 후보 식별은 공격 행위 탐지와 별개입니다. 기존 위협 분석의 `SemanticRiskAdapter`는 키워드 기반이며 BERT 모델이 아닙니다. PII 모델은 기본적으로 꺼져 있고, 시작이나 분석 시 네트워크 호출·모델 자동 다운로드를 하지 않습니다.

## 선택한 모델과 확인 범위

[YATAV-ENT/aegis-personal-pii-ner](https://huggingface.co/YATAV-ENT/aegis-personal-pii-ner)는 모델 카드 기준 한국어·영어를 대상으로 하는 multilingual BERT 토큰 분류 모델입니다. ONNX INT8 파일과 토크나이저가 제공되며 모델 카드에 Apache-2.0이 표시됩니다. 이 구현은 명시적으로 준비한 로컬 파일과 ONNX Runtime CPU를 사용합니다. 다른 언어의 품질은 확인되지 않았습니다.

모델 카드의 18개 후보 유형은 `GIVENNAME`, `SURNAME`, `USERNAME`, `EMAIL`, `TELEPHONENUM`, `DATEOFBIRTH`, `CREDITCARDNUMBER`, `IDCARD`, `STREET`, `CITY`, `ZIPCODE`, `BUILDINGNUM`, `IP_ADDRESS`, `PASSWORD`, `ACCOUNTNUM`, `DRIVERLICENSENUM`, `TIME`, `COMPANY`입니다. BIO 라벨은 이 유형의 B/I와 O를 합쳐 37개입니다. 이 목록은 모델이 출력할 수 있는 유형이며, 모든 사례를 정확히 탐지한다는 보장은 아닙니다. 위 목록 밖의 유형은 모델의 지원을 주장하지 않습니다.

기준 리비전은 `3a1d4f61e156035a22d820b59c78e4d5e5cc6f6f`입니다. 해당 리비전에서 파일을 내려받아 SHA-256을 계산하고, ONNX의 LFS SHA-256과 나머지 파일의 Git blob ID를 Hugging Face 리비전 메타데이터와 대조했습니다. 로더는 다음 **여섯 파일 모두의 SHA-256**을 확인한 뒤 라벨·BERT 설정, 토크나이저 어휘 크기와 특수 토큰을 검사합니다. 토크나이저는 확인된 설정 파일만 임시 디렉터리에 복사하여 로드하므로, 같은 폴더의 다른 파일은 토큰화에 영향을 주지 않습니다. 파일이 누락되거나 변조되면 모델은 준비 상태가 되지 않습니다.

| 파일 | SHA-256 |
| --- | --- |
| `onnx/model_quantized.onnx` | `8cb91734f9a559c8a2dd127484582b9bc7c43bae21cc44b6c893321030ae3de3` |
| `config.json` | `704c0412effea86fca8f9dfc61c45b83ebba27a09dde1e697b29bfc2a9b835a3` |
| `tokenizer.json` | `68376ce5e989db0c0bdb282422a99e12e449c1f97a1a18daf705626db0d57b83` |
| `tokenizer_config.json` | `cbef04fcea9edfbabfe9d20fde7eda79a5a6932d057308bb2b021dd7afd5ccab` |
| `special_tokens_map.json` | `5d5b662e421ea9fac075174bb0688ee0d9431699900b90662acd44b2a350503a` |
| `vocab.txt` | `fe0fda7c425b48c516fc8f160d594c8022a0808447475c1a7c6d6479763f310c` |

Google Colab Linux x86-64의 Python 3.13.18, ONNX Runtime 1.31.1과 Transformers 4.57.6에서 이 공식 파일들을 직접 열어 한국어·영어 합성 문장에 CPU 추론을 실행했습니다. 세 입력은 `input_ids`, `attention_mask`, `token_type_ids`이고 출력은 각 토큰에 대한 37개 점수로, 현재 로더의 기대 형식과 일치했습니다. 실제 Fast 토크나이저는 미리 토큰화한 ID에서 `return_special_tokens_mask=True`를 요청하면 예외를 발생시켰습니다. 수정 방식인 특수 토큰 ID 배열 확인과 위치 기반 마스크로 단독 추론에 성공했고, 287토큰 합성 입력을 네 개 창으로 처리해 끝부분에 도달했습니다. 이 단독 모델 실험은 PR 코드 전체의 통합 검증과 별개입니다. 로컬 Mac과 Windows에서 실제 모델을 실행했는지는 아래 테스트를 통해 따로 확인해야 합니다.

모델 카드에는 학습 데이터로 `ai4privacy/pii-masking-400k`가 표시되며, 이 [데이터셋의 현재 사용 조건](https://huggingface.co/datasets/ai4privacy/pii-masking-400k/blob/main/license.md)은 모델 카드의 라이선스 표기와 별도로 검토할 필요가 있습니다. 학습 당시 데이터 조건과 모델 배포 권한은 이 저장소에서 확인하지 못했으므로 실제 배포 또는 상용 사용 전 모델 제작자에게 확인하세요.

## 명시적 준비와 오프라인 사용

인터넷에 연결된 환경에서 한 번만 다음 명령을 실행합니다. 모델 파일은 약 178 MB이며 저장소 바깥에 둡니다. Python 환경은 기존 빠른 시작에서 만든 가상환경을 사용하세요.

```bash
pip install -r requirements-pii.txt
python -c 'from pathlib import Path; from huggingface_hub import snapshot_download; snapshot_download(repo_id="YATAV-ENT/aegis-personal-pii-ner", revision="3a1d4f61e156035a22d820b59c78e4d5e5cc6f6f", local_dir=str(Path.home()/".aegis-on/models/pii-v2"))'
export AEGIS_PII_MODEL_DIR="$HOME/.aegis-on/models/pii-v2"
uvicorn --app-dir src aegis_on.api:app --reload
```

파일이 준비된 뒤에는 위 환경 변수를 설정하고 서버를 시작하면 됩니다. 로더는 `local_files_only=True`와 CPU 실행 공급자를 사용합니다. `onnx/model_quantized.onnx`, `config.json`, 토크나이저 파일이 모두 필요하며 `requirements-pii.txt`의 NumPy·ONNX Runtime·Transformers가 추가로 필요합니다. 커밋 `74cabff26dfe27eb14fa7070870f7447dae5b733`의 로더와 실제 모델은 Google Colab Linux x86-64 CPU에서 통합 테스트했습니다. macOS에서도 로컬 CPU 경로를 사용하도록 구성했지만 이 구현을 실제 macOS 모델 파일로 통합 검증하지는 못했습니다.

실제 파일을 준비한 뒤 저장소 루트에서 다음 통합 테스트를 실행하세요. `AEGIS_PII_MODEL_DIR`는 위에서 설정한 로컬 경로여야 합니다. 성공하면 두 테스트가 `OK`로 끝납니다. 파일이 없거나 해시가 다르면 초기화 테스트가 실패하며, 기본 테스트에서 이 두 항목은 건너뜁니다.

```bash
AEGIS_PII_INTEGRATION=1 PYTHONPATH=src python -m unittest discover -s tests -p 'test_pii_real_model.py' -v
PYTHONPATH=src python -m aegis_on.pii_evaluation --dataset evaluation/pii_synthetic_v1.json
```

평가 결과에서 `model_only.available`이 `true`여야 실제 모델 점수가 표시됩니다. `false`이면 모델의 점수를 측정하지 못한 것이므로 정규식 점수와 혼동하지 마세요. 모델 파일은 저장소에 추가하지 않으며 `.gitignore`는 로컬 `models/`, `*.onnx`, `*.safetensors`를 제외합니다.

Windows PowerShell에서는 파일 준비 후 `$env:AEGIS_PII_MODEL_DIR = "$HOME\.aegis-on\models\pii-v2"`를 설정하고 기존 README의 서버 실행 명령을 사용합니다. 인증된 `GET /api/v1/pii/status` 또는 분석 결과의 `pii`에서 `disabled`, `ready`, `error`를 확인합니다. `ready`는 로컬 세션과 안전한 고정 문자열에 대한 초기 추론이 성공한 상태입니다. 초기화 실패 시 정규식은 유지하고 원인을 유형별로 표시합니다. 분석 중 모델이 실패하면 그 요청은 503으로 실패하고, 상태는 `error`가 됩니다. 서버 설정과 파일을 확인한 후 재시작하세요.

## 처리 범위와 한계

JSON과 유효한 Sysmon ID 1·3 이벤트의 호스트, 사용자, 프로세스·부모 프로세스, 명령줄·경로, 출발지·목적지 및 이벤트 ID 문자열을 검사합니다. 미지원·오류 Sysmon 항목, 임의 JSON 키와 별도 비문자열 데이터는 검사 범위가 아닙니다. JSON 이벤트의 텍스트 필드에 문자열이 아닌 값이 들어오면 검사를 우회하지 못하도록 거부합니다. PII 결과는 원문 대신 입력 위치, 필드, 후보 유형, 출처와 가명 토큰을 표시합니다.

Sysmon 원본 연결 정보의 다른 문자열 필드와 레코드 ID·프로세스 ID·포트 숫자 필드도 **검사 대상 필드에서 이미 찾은 값이 반복되면** 표시 전에 가립니다. 숫자 필드는 일치할 때만 가명 문자열로 표시하고 그 외에는 기존 숫자 형식을 유지합니다. 해당 메타데이터를 독립적으로 모델에 넣어 검사한다는 뜻은 아닙니다. 승인 담당자와 사유는 함께 검사한 후 승인 기록에 표시합니다. API 오류에는 원본 입력을 넣지 않습니다. 서버의 보안 로그, 외부 프록시, 브라우저 확장, 시스템 수집 로그까지 검사하거나 보호하는 기능은 아닙니다.

정규식은 ASCII 이메일, `01`로 시작하는 한국 휴대전화 형식과 IPv4·IPv6를 대상으로 합니다. 한국어 이름, 해외 전화번호와 그 외 개인정보의 완전한 탐지를 보장하지 않습니다. IPv4-mapped IPv6는 같은 IPv4와 동일한 토큰으로 취급합니다. 모델과 정규식의 겹친 탐지 구간은 표시할 때 합집합을 가리되, 내부 후보가 다른 필드에서 반복되면 그 후보도 가립니다. 탐지 엔진이 근거를 소문자로 변환할 수 있으므로 이미 탐지한 값은 대소문자가 다른 표시에도 가림 처리를 적용합니다. 탐지된 ISO 날짜·시각이 상관분석에서 시간대 형식으로 변환되는 경우에도 변환된 표기를 가립니다. `token`은 개별 후보의 가명이고 `display_token`은 겹침을 합쳐 실제 표시한 가명입니다. 유형과 원문이 같은 반복 후보는 동일한 개별 토큰을 사용합니다. 모델별 평가에서는 중첩을 합치기 전의 예측을 사용합니다.

대시보드에서는 사용자가 선택한 파일의 이름을 표시하지 않습니다. 모델 추론 오류는 인증 설정 오류와 구별하며, 예상하지 못한 서버 오류의 상세 원문은 표시하지 않습니다.

토크나이저 설정의 `max_length=128`, 모델 위치 한도 512를 확인했습니다. 구현은 특수 토큰을 포함해 최대 128 토큰의 겹친 창으로 긴 문자열 전체를 처리합니다. 창 경계에 걸려 잘린 부분 예측은 다른 창의 동일 유형 전체 예측에 포함될 때만 제거하고, 서로 다른 예측은 유지합니다. 창 간 예측이 다르거나 전체 구간이 한 창에 들어가지 않으면 중복 또는 부분 결과가 남을 수 있습니다. 모델 활성화 시 한 요청의 검사 대상 문자열 합계가 250,000자를 넘으면 안전하게 요청을 거부합니다. 요약에는 최대 500개 후보를 반환하고 추가 후보의 표시 생략을 알립니다. 실제 모델의 긴 입력과 경계 처리는 소수 합성 사례로만 확인했으며 실제 환경의 품질은 검증하지 못했습니다.

탐지되지 않은 값은 원문으로 남을 수 있습니다. 기존 표시용 토큰은 고정 salt의 짧은 해시이므로 완전한 익명화가 아니며 추측 가능한 값은 역추정될 수 있습니다. 원본을 신뢰할 수 있는 환경에서만 처리하고 보고서·서버 접근을 제한하세요. 개인정보 구간 평가는 [별도 평가 문서](pii_evaluation.md)에 있으며 실제 공격 지표와 혼합하지 않습니다.
