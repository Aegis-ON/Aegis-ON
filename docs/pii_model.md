# 로컬 PII NER

개인정보 후보 식별은 공격 행위 탐지와 별개입니다. 기존 위협 분석의 `SemanticRiskAdapter`는 키워드 기반이며 BERT 모델이 아닙니다. PII 모델은 기본적으로 꺼져 있고, 시작이나 분석 시 네트워크 호출·모델 자동 다운로드를 하지 않습니다.

## 선택한 모델과 확인 범위

[YATAV-ENT/aegis-personal-pii-ner](https://huggingface.co/YATAV-ENT/aegis-personal-pii-ner)는 모델 카드 기준 한국어·영어를 대상으로 하는 multilingual BERT 토큰 분류 모델입니다. ONNX INT8 파일과 토크나이저가 제공되며 모델 카드에 Apache-2.0이 표시됩니다. 이 구현은 명시적으로 준비한 로컬 파일과 ONNX Runtime CPU를 사용합니다. 다른 언어의 품질은 확인되지 않았습니다.

모델 카드의 18개 후보 유형은 `GIVENNAME`, `SURNAME`, `USERNAME`, `EMAIL`, `TELEPHONENUM`, `DATEOFBIRTH`, `CREDITCARDNUMBER`, `IDCARD`, `STREET`, `CITY`, `ZIPCODE`, `BUILDINGNUM`, `IP_ADDRESS`, `PASSWORD`, `ACCOUNTNUM`, `DRIVERLICENSENUM`, `TIME`, `COMPANY`입니다. BIO 라벨은 이 유형의 B/I와 O를 합쳐 37개입니다. 이 목록은 모델이 출력할 수 있는 유형이며, 모든 사례를 정확히 탐지한다는 보장은 아닙니다. 위 목록 밖의 유형은 모델의 지원을 주장하지 않습니다.

참고 모델 저장소 리비전은 `3a1d4f61e156035a22d820b59c78e4d5e5cc6f6f`이고 ONNX 파일의 SHA-256은 `8cb91734f9a559c8a2dd127484582b9bc7c43bae21cc44b6c893321030ae3de3`입니다. 로더는 ONNX 해시, 라벨·BERT 설정과 토크나이저의 어휘 크기·특수 토큰을 확인하지만 **토크나이저 파일 자체의 독립 해시는 검증하지 않습니다**. 신뢰할 수 있는 동일 리비전의 파일을 함께 준비해야 하며, 로컬 파일이 변조되지 않았음을 별도 확인하세요. 로컬 테스트 환경에서는 모델 파일과 ONNX Runtime에 접근하지 못해 실제 로드·추론을 검증하지 못했습니다.

모델 카드에는 학습 데이터로 `ai4privacy/pii-masking-400k`가 표시되며, 이 [데이터셋의 현재 사용 조건](https://huggingface.co/datasets/ai4privacy/pii-masking-400k/blob/main/license.md)은 모델 카드의 라이선스 표기와 별도로 검토할 필요가 있습니다. 학습 당시 데이터 조건과 모델 배포 권한은 이 저장소에서 확인하지 못했으므로 실제 배포 또는 상용 사용 전 모델 제작자에게 확인하세요.

## 명시적 준비와 오프라인 사용

인터넷에 연결된 환경에서 한 번만 다음 명령을 실행합니다. 모델 파일은 약 178 MB이며 저장소 바깥에 둡니다. Python 환경은 기존 빠른 시작에서 만든 가상환경을 사용하세요.

```bash
pip install -r requirements-pii.txt
python -c 'from pathlib import Path; from huggingface_hub import snapshot_download; snapshot_download(repo_id="YATAV-ENT/aegis-personal-pii-ner", revision="3a1d4f61e156035a22d820b59c78e4d5e5cc6f6f", local_dir=str(Path.home()/".aegis-on/models/pii-v2"))'
export AEGIS_PII_MODEL_DIR="$HOME/.aegis-on/models/pii-v2"
uvicorn --app-dir src aegis_on.api:app --reload
```

파일이 준비된 뒤에는 위 환경 변수를 설정하고 서버를 시작하면 됩니다. 로더는 `local_files_only=True`와 CPU 실행 공급자를 사용합니다. `onnx/model_quantized.onnx`, `config.json`, 토크나이저 파일이 모두 필요하며 `requirements-pii.txt`의 NumPy·ONNX Runtime·Transformers가 추가로 필요합니다. macOS에서도 로컬 CPU 경로를 사용하도록 구성했지만 이 구현을 실제 macOS 모델 파일로 통합 검증하지는 못했습니다.

Windows PowerShell에서는 파일 준비 후 `$env:AEGIS_PII_MODEL_DIR = "$HOME\.aegis-on\models\pii-v2"`를 설정하고 기존 README의 서버 실행 명령을 사용합니다. 인증된 `GET /api/v1/pii/status` 또는 분석 결과의 `pii`에서 `disabled`, `ready`, `error`를 확인합니다. `ready`는 로컬 세션과 안전한 고정 문자열에 대한 초기 추론이 성공한 상태입니다. 초기화 실패 시 정규식은 유지하고 원인을 유형별로 표시합니다. 분석 중 모델이 실패하면 그 요청은 503으로 실패하고, 상태는 `error`가 됩니다. 서버 설정과 파일을 확인한 후 재시작하세요.

## 처리 범위와 한계

JSON과 유효한 Sysmon ID 1·3 이벤트의 호스트, 사용자, 프로세스·부모 프로세스, 명령줄·경로, 출발지·목적지 및 이벤트 ID 문자열을 검사합니다. 미지원·오류 Sysmon 항목, 임의 JSON 키와 별도 비문자열 데이터는 검사 범위가 아닙니다. JSON 이벤트의 텍스트 필드에 문자열이 아닌 값이 들어오면 검사를 우회하지 못하도록 거부합니다. PII 결과는 원문 대신 입력 위치, 필드, 후보 유형, 출처와 가명 토큰을 표시합니다.

정규식은 ASCII 이메일, `01`로 시작하는 한국 휴대전화 형식과 IPv4·IPv6를 대상으로 합니다. 한국어 이름, 해외 전화번호와 그 외 개인정보의 완전한 탐지를 보장하지 않습니다. IPv4-mapped IPv6는 같은 IPv4와 동일한 토큰으로 취급합니다. 모델과 정규식의 겹친 탐지 구간은 표시할 때 합집합을 가립니다. 반복 값은 같은 토큰을 사용합니다. 모델별 평가에서는 중첩을 합치기 전의 예측을 사용합니다.

토크나이저 설정의 `max_length=128`, 모델 위치 한도 512를 확인했습니다. 구현은 특수 토큰을 포함해 최대 128 토큰의 겹친 창으로 긴 문자열 전체를 처리합니다. 창 경계에 걸려 잘린 부분 예측은 다른 창의 동일 유형 전체 예측에 포함될 때만 제거하고, 서로 다른 예측은 유지합니다. 창 간 예측이 다르거나 전체 구간이 한 창에 들어가지 않으면 중복 또는 부분 결과가 남을 수 있습니다. 모델 활성화 시 한 요청의 검사 대상 문자열 합계가 250,000자를 넘으면 안전하게 요청을 거부합니다. 요약에는 최대 500개 후보를 반환하고 추가 후보의 표시 생략을 알립니다. 개체 경계와 긴 입력의 실제 모델 품질은 미검증입니다.

탐지되지 않은 값은 원문으로 남을 수 있습니다. 기존 표시용 토큰은 고정 salt의 짧은 해시이므로 완전한 익명화가 아니며 추측 가능한 값은 역추정될 수 있습니다. 원본을 신뢰할 수 있는 환경에서만 처리하고 보고서·서버 접근을 제한하세요. 개인정보 구간 평가는 [별도 평가 문서](pii_evaluation.md)에 있으며 실제 공격 지표와 혼합하지 않습니다.
