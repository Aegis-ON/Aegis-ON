# 명령줄 분류 실험

이 기능은 **작은 합성 데이터로 미세조정한 실험용 프로토타입**입니다. 모델 출력은 관제 검토 후보 신호이며 실제 공격 확정, 검증된 공격 확률 또는 ATT&CK 기법 판정이 아닙니다. 실제 명령은 실행하지 않습니다. PII NER과 별도의 모델·데이터·평가입니다. 규칙·키워드·네트워크 상관분석과 승인 시뮬레이션은 그대로 동작합니다.

## 기반 모델과 학습 데이터

[Google BERT-Tiny](https://huggingface.co/google/bert_uncased_L-2_H-128_A-2), revision `30b0a37ccaaa32f332884b96992754e246e48c5f`는 카드에 Apache-2.0으로 표기된 영문 uncased 사전학습 모델(2층, 약 4.4M 매개변수)입니다. 원래 공격 분류기가 아니며 별도 분류층을 학습합니다. 가중치 파일은 약 17.7MB입니다. 사전학습 출처는 BERT 연구의 BookCorpus와 영어 위키피디아이며, 모델 카드의 라이선스 표기와 원천 학습 코퍼스의 개별 사용 조건은 구분해야 합니다. 한국어·명령 난독화·Windows 환경에서의 성능은 확인되지 않았습니다.

`evaluation/command_synthetic_v2.json`은 이 작업에서 직접 작성한 가상 텍스트 44건입니다. 외부 공격 로그나 PR #4 데이터를 학습에 넣지 않았습니다. `positive`는 해당 합성 시나리오에서 **검토가 필요하다고 주석한 신호**로, 실행 성공이나 악성 의도 정답이 아닙니다. 예를 들어 encoded 명령도 단순 인코딩 신호로 검토 대상에 넣었으며 일부 실제 내용은 무해합니다. `unknown`은 맥락이 없어 점수에서 제외합니다. 개인정보나 인증 정보는 의도적으로 넣지 않았습니다. 예시 문구를 텍스트로만 분석하고 실행하지 마세요.

| 분할 | 사례 수 | 명령군 수 | 목적 |
| --- | ---: | ---: | --- |
| train | 24 | 12 | 학습, 양성·음성 각 12 |
| validation | 8 | 4 | epoch 선택, 양성·음성 각 4 |
| test | 8 | 4 | 소규모 내부 확인, 양성·음성 각 4 |
| ambiguous | 4 | 2 | 정답 불명 출력 확인, 지표 제외 |

각 그룹은 사례 2개를 포함하며 경로·옵션만 달라질 수 있어 독립 표본이 아닙니다. 그룹은 수작업으로 배정했습니다. `validate_data`는 그룹의 분할 충돌, 정규화한 정확 중복과 PR #4에 대한 train/validation의 정확 중복을 검사합니다. 유사 변형이나 그룹 지정의 정확성은 자동으로 보장하지 않습니다. 실제로 PR #4 평가셋과 이 학습셋에는 같은 명령 계열의 유사 사례가 있으므로 PR #4를 독립 테스트로 취급할 수 없습니다. 개발 중 이미 본 이 test도 최종 독립 성능셋이 아닙니다.

공개 데이터 후보 [shell-safety-v1.1](https://huggingface.co/datasets/tomngdev/shell-safety-v1.1)은 MIT 표기의 합성 명령·실행 문맥을 제공하지만 allow/ask/deny는 에이전트 권한 라벨이라 공격 라벨로 바로 사용할 수 없습니다. [PowerShell 스크립트 데이터](https://huggingface.co/datasets/wwe123/Benign_and_malicious_PowerShell_scripts)는 스크립트 단위이며 카드에서 라이선스를 확인하지 못했습니다. 둘 다 사용하지 않았습니다. 실환경 평가에는 권한이 확인되고 민감 정보가 제거된 다양한 정상 관리·의심 로그와 독립 전문가 주석이 필요합니다.

## 준비와 재현

기본 실행은 공격 모델을 다운로드하거나 외부에 호출하지 않습니다. 다음은 명시적 준비·실험 단계입니다. 모델과 데이터는 저장소 밖에 두고 직접 출처와 파일을 확인하세요.

```bash
pip install -r requirements.txt -r requirements-attack.txt
pip install huggingface_hub
python -c "from huggingface_hub import snapshot_download; snapshot_download('google/bert_uncased_L-2_H-128_A-2', revision='30b0a37ccaaa32f332884b96992754e246e48c5f', local_dir='/tmp/aegis-bert-base', allow_patterns=['config.json','vocab.txt','model.safetensors'])"
PYTHONPATH=src python -m aegis_on.attack_experiment --base /tmp/aegis-bert-base --dataset evaluation/command_synthetic_v2.json --prior evaluation/synthetic_v1.json --output /tmp/aegis-attack-model
```

학습 스크립트는 사전학습 가중치 SHA-256 `7fb69ad9f6866d8983183c930e33828f326470bf6ad8bbb2ad4ed957a92e9414`와 config/vocab Git blob을 검증하고 예상 밖 최상위 파일을 거부합니다. seed 42, CPU, AdamW 3e-5, 배치 4, 6 epoch, validation loss가 가장 낮은 checkpoint, 사전 고정 threshold 0.5입니다. `test` 결과가 즉시 출력되므로 반복적인 튜닝 후에는 이 데이터도 개발셋으로 취급해야 합니다. train·validation 입력이 128 토큰을 넘으면 학습이 실패하고 test·ambiguous 입력 초과는 해당 사례를 미평가로 제외합니다.

```bash
export AEGIS_ATTACK_MODEL_DIR=/tmp/aegis-attack-model
```

서버를 재시작하면 설정한 로컬 safetensors·토크나이저를 CPU로 로드합니다. 별도 실모델 테스트는 `AEGIS_ATTACK_INTEGRATION=1 PYTHONPATH=src python -m unittest discover -s tests -p test_attack_real_model.py -v`로 실행합니다. 모델 파일은 Git에 넣지 않습니다. 모델은 별도 신뢰 가능한 위치에서 준비해야 하며, 표시되는 각 파일 SHA-256은 식별을 돕지만 신뢰할 수 있는 원본과 대조하지 않으면 진위나 학습 출처를 증명하지 않습니다. 파일 교체 권한을 제한하세요. 명령에 한해 공백·누락, 잘못된 자료형, 20,000자 또는 128 토큰 초과, 추론 실패를 별도 상태로 표시하며 잘라서 정상 처리하지 않습니다. 0.5 미만은 **기준 미충족**이지 안전 판정이 아닙니다. 모델이 모호한 맥락을 자동으로 판별하거나 보류할 수 있다고 주장하지 않습니다.

### 기존 모델 보존과 재평가

이 실험의 원래 가중치와 설정·토크나이저 여섯 파일, 합성 데이터 및 생성 설정과 파일별 SHA-256을 비공개 보존 ZIP에 넣었습니다. 모델 폴더와 메타데이터는 별도 신뢰 위치에서 보호하세요. 이 기록은 실제 Colab 학습 셀을 PR 학습 스크립트가 실행된 것으로 주장하지 않습니다. 재학습해도 환경과 연산 차이로 같은 가중치 해시를 보장하지 않으며 옵티마이저·난수 상태를 보존하지 않아 중단된 학습을 이어가는 체크포인트가 아닙니다.

보존 ZIP을 저장소 외부의 새 디렉터리에 풀고, `metadata.json`의 `sha256` 항목을 별도로 신뢰한 값과 비교하세요. 아래처럼 지정하면 로더도 여섯 파일과 해당 목록을 대조해 불일치 시 로드를 실패시킵니다. 목록까지 함께 변조될 수 있으므로 독립적으로 보호된 원본 해시와 비교해야 하며 해시 자체가 출처나 라이선스를 인증하지는 않습니다. 변수 미설정 시 기존처럼 해시를 식별용으로만 표시합니다.

```bash
export AEGIS_ATTACK_MODEL_DIR=/path/to/unpacked/model
export AEGIS_ATTACK_MODEL_MANIFEST=/path/to/unpacked/metadata.json
AEGIS_ATTACK_INTEGRATION=1 PYTHONPATH=src python -m unittest discover -s tests -p test_attack_real_model.py -v
PYTHONPATH=src python -c "import json,os; from aegis_on.attack_experiment import evaluate; m=json.load(open(os.environ['AEGIS_ATTACK_MODEL_MANIFEST'])); evaluate('evaluation/command_synthetic_v2.json',os.environ['AEGIS_ATTACK_MODEL_DIR'],report=m)"
```

평가 출력의 `evaluation_dataset_sha256`은 실제 입력 파일의 해시이고 `training_dataset_matches`는 학습 당시 사용한 전체 데이터셋 JSON 파일의 해시와 바이트 단위로 비교한 결과입니다. 전체 파일에는 학습·검증·시험·판단 불가 분할이 모두 포함됩니다. `false`면 서로 다른 파일이며 `null`이면 학습 데이터 해시가 없어 비교할 수 없습니다. 이는 유사 명령의 누출이나 데이터 출처를 검증하지 않습니다. 이 모델은 PII NER 모델과 별개입니다.

## 실제 Colab 측정

Colab Linux x86-64 Python 3.13.18, PyTorch 2.14.1+cpu, Transformers 4.57.6. 기반 revision의 세 파일은 HF revision metadata와 무결성을 대조했고, 위와 같은 설정으로 별도 notebook 셀에서 실제 학습해 validation loss 기준 6 epoch를 선택했습니다. 학습한 `model.safetensors` SHA-256은 `c33ad158789d3b57d60947ac89346ade3eec16c0045b381356fed423c025bf28`입니다. 학습 셀은 저장소의 재현 스크립트와 같은 설정을 사용했지만 **스크립트 자체를 실행한 것은 아닙니다**. 저장된 모델을 PR 로더 소스의 SHA-256을 확인한 후 CPU에 다시 로드했습니다.

동일 test 8건, 0.5 임계값, event 단위, 양성은 합성 검토 주석입니다. 아래 baseline은 실제 규칙과 키워드 구현을 사용했지만 process는 명령 첫 토큰으로 합성하고 parent는 비웠습니다. 모델은 명령만 받습니다. 결합 제품 점수는 구현하지 않았습니다.

| 방식 | TP | FP | TN | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 규칙·키워드 | 2 | 0 | 4 | 2 | 1.000 | 0.500 | 0.667 |
| 실제 미세조정 모델 | 4 | 3 | 1 | 0 | 0.571 | 1.000 | 0.727 |

모델 오탐은 `test-normal-whoami-1`, `test-normal-whoami-2`, `test-normal-search-2`이며 미탐은 없었습니다. 기준선 미탐은 `test-sus-rundll-1`, `test-sus-rundll-2`입니다. 판단 불가 4건 중 모델은 2건을 검토 후보로 표시했고 나머지 2건은 기준 미충족으로 표시했습니다. 이것이 해당 사례의 실제 의도 판정은 아닙니다. 시험 8건은 4개 그룹의 변형으로 실제 환경 성능이나 공격 탐지율을 입증하지 않습니다. 모델 점수는 softmax 값이며 교정된 실제 공격 확률이 아닙니다.

PII 후보 검사가 먼저 마스킹 함수를 만들고, 위협 분석은 메모리의 원문 명령을 입력으로 사용한 뒤 결과의 이벤트 식별자를 기존 방식으로 가립니다. 명령 원문은 모델 결과에 반환하지 않습니다. PII 모델의 미탐은 다른 출력 경로에 남을 수 있습니다. 모델·규칙 결과와 PII는 별도 상태이며 원본 로그는 외부 API로 보내지 않습니다.
