# 명령줄 공격 분석 연구 상태

**공격 분류 모델은 아직 준비되지 않았습니다.** 현재 API와 대시보드는 `unavailable`을 표시합니다. 로컬 모델 로더나 제품 결합 결과는 구현하지 않았고 모델 다운로드 또는 외부 추론도 수행하지 않습니다. 기존 규칙·키워드 기반 휴리스틱·네트워크 상관분석과 PII NER은 그대로 사용합니다. PII NER은 공격 분류 모델이 아닙니다. 이 문서는 후보 조사와 합성 데이터 기반 평가 준비를 기록합니다.

## 후보와 도입 보류 사유

- [Genos](https://huggingface.co/genos-security/genos): CodeBERT 기반 gatekeeper는 단일 명령을 Benign (0), Malicious (1), Context_Dependent (2)로 분류합니다. 영문 명령, 최대 256 토큰으로 문맥과 긴 입력에 한계가 있습니다. ATT&CK 기법 ID 출력은 아닙니다. 확인한 revision은 `36ae71cea3a1e22b002c2cb685d0b59aaa2188d9`입니다. 카드 상단 Apache-2.0 표기와 본문의 가중치 라이선스 미선언 문구가 충돌하므로 권리 확인이 필요합니다. `.pt`는 별도 backbone과 `genos_api` 코드가 필요한 pickle이며 일반 Transformers 체크포인트가 아닙니다. 카드에 따르면 학습은 약한 라벨에 의존하고 구성요소 간 학습·평가 중복이 있으며 일부 정상 명령에 오탐이 있습니다. CPU 성능이나 Aegis 연동은 검증하지 않았습니다.
- [PowerShell RoBERTa](https://huggingface.co/fetterm4n/finetuned-roberta-powershell-detector): PowerShell 용 benign (0)/malicious (1) 분류를 주장하며 확인 revision은 `84bd8d43fe34c5f15716a368af3d212a4981cb7b`입니다. 카드의 라이선스 문구는 선택되지 않은 자리표시자이고 학습 데이터 출처·분할과 config의 라벨 매핑을 충분히 확인할 수 없습니다. PowerShell 외 명령과 기법 분류에 적합하다고 가정하지 않습니다.
- [CodeBERT base](https://huggingface.co/microsoft/codebert-base)는 사전학습 모델이지 검증된 명령줄 공격 분류기가 아닙니다. 가중치만 연결해 공격 판단을 만들지 않습니다.

위 후보를 실제로 다운로드, 로드 또는 추론하지 않았으며 모델 성능 수치는 없습니다. Mac CPU 적합성은 미확인입니다. PII 모델을 재활용하지 않습니다. 모델 선택에는 라이선스·데이터 출처 및 분할·라벨 의미를 확인하고, 오프라인 로드, 파일/토크나이저 revision과 해시, 입력 길이, 실패 처리 및 CPU 통합 검증이 필요합니다. 모델 점수는 교정 검증 전 실제 공격 확률이나 기존 규칙 점수와 동일하지 않으며, 출력에 없는 ATT&CK 기법을 생성하지 않습니다.

## 데이터 준비

기존 합성 manifest의 `dev` 중 유효한 Event 1이고 명령줄이 있으며 정답이 positive/negative인 사례만 내보냅니다. `eval`, 판단 불가, 입력 오류 및 네트워크 배치를 내보내지 않습니다. 전체 manifest의 사례 ID, 그룹, 정규화 명령 및 정확한 이벤트의 교차 분할 검증을 먼저 수행합니다. 현재 dev 출력은 **6개뿐**이며 배선 확인용이지 실용적인 학습 데이터가 아닙니다. positive는 합성 시나리오의 관제 검토 라벨이며 실제 악성 확정 라벨이 아닙니다.

```bash
PYTHONPATH=src python -m aegis_on.attack_research \
  --dataset evaluation/synthetic_v1.json --output /tmp/aegis-command-dev.json
```

출력은 명령 원문, 사례·그룹 ID와 라벨을 포함합니다. `synthetic: true` 표기는 검증 가능한 합성 여부의 증명이 아닙니다. 실사용 로그나 비밀값을 입력하지 말고 출력 파일 접근을 제한하세요. 학습 시에는 command와 label만 모델에 제공하고 case/group ID와 설명을 모델 입력에서 빼야 합니다. 같은 시나리오/템플릿 단위로 학습·검증·독립 시험을 분리하고 정규화 중복 및 유사성을 추가로 수동 검토해야 합니다. 자동 검사는 모든 유사 변형이나 외부 데이터와의 중복을 식별할 수 없습니다. 기존 `eval`도 개발 중 이미 살펴본 소규모 합성 사례이므로 독립적인 최종 성능 평가가 아닙니다.

공개 데이터 후보 [shell-safety-v1.1](https://huggingface.co/datasets/tomngdev/shell-safety-v1.1)은 카드에 MIT로 표시된 합성 명령과 실행 문맥의 allow/ask/deny 데이터입니다. 이는 에이전트 권한 결정 라벨이므로 공격 정답으로 자동 변환할 수 없으며, 기존 평가셋과의 중복 및 분할 독립성도 아직 확인하지 않았습니다. [PowerShell 스크립트 데이터](https://huggingface.co/datasets/wwe123/Benign_and_malicious_PowerShell_scripts)는 스크립트 단위이며 카드에서 라이선스를 확인하지 못했고 데이터 뷰어 오류가 있었습니다. 어느 데이터도 다운로드하거나 학습에 사용하지 않았습니다. 이용 전 출처·라이선스·주석·중복·민감 정보 및 명령줄/스크립트 단위 차이를 검토해야 합니다.

## 평가 인터페이스

기존 기준선 명령:

```bash
PYTHONPATH=src python -m aegis_on.evaluation --dataset evaluation/synthetic_v1.json --split eval
```

`aegis_on.attack_research.compare_commands`는 추후 구현자가 제공하는 `predict(command)` 계약에 대해 모델과 기준선을 **공통으로 평가 가능한 사건**에서 비교하는 연구용 함수입니다. `suspicious`, `benign`, `abstain`만 허용합니다. 빈 명령, 무효 입력, 미지원, 정답 불명, 모델 예외·미지원 출력은 음성으로 계산하지 않고 제외 수와 알려진 정답 분포를 기록합니다. 전부 실패하거나 거부하면 비교 점수를 내지 않습니다. OR 결합은 연구용 계산일 뿐 제품 결합 기능이 아닙니다. 후보 모델의 실제 라벨을 이 관제 정답에 대응시키려면 별도 근거가 필요합니다. 특히 Genos의 Context_Dependent는 정상으로 바꾸지 말고 평가 보류로 다뤄야 합니다. 예측기에는 원문 명령 외 case ID·정답·설명을 제공하지 않습니다.

같은 사례 비교라도 기존 키워드 기준선은 프로세스와 부모 프로세스도 입력에 사용하고, 모델 계약은 명령줄만 사용하므로 입력 정보가 동일하지 않습니다. 제외가 많은 비교는 성공 사례의 부분집합 결과입니다. 팬아웃은 별도 배치 단위이며 여기서 점수화하지 않습니다. PII 성능과 공격 분석 성능도 별개입니다.

현재 구현은 실모델의 로드 성공·실패, 긴 입력, 결과·원본 이벤트 연결과 모델 기반 화면을 검증할 수 없습니다. 모델 통합 전 해당 기능과 테스트를 구현해야 합니다. 분석 API는 PII 후보 검사를 마친 후 원문 이벤트로 기존 위협 엔진을 실행하고, 응답의 표시 항목을 가명처리합니다. 탐지되지 않은 PII는 남을 수 있습니다. 공격 모델을 추가할 때도 사용자 로그를 외부로 보내지 말고 원문·예외가 응답이나 로그에 노출되지 않도록 해야 합니다.
