# 합성 Sysmon 데이터에서 CodeBERT AP 개선

같은 [합성 로그 384건](../evaluation/codebert_synthetic_demo_v2/README.md)에서 CodeBERT 검증 AP가 **0.722 → 0.805**, 상위 10건의 조사 필요 사례가 **7 → 9건**으로 개선됐다. 검증·평가 AP는 확정 라벨 42건에 대해 계산했고, 상위 10건은 판단 보류를 포함한 후보 56건에서 뽑았다.

| 후보 | 검증 AP | 상위 10건의 조사 필요 |
| --- | ---: | ---: |
| 기존 CodeBERT | 0.72159 | 7 |
| 기존 문자 TF-IDF | 0.74530 | 7 |
| 마지막 네 층 이어 학습 (`resume-four`) | 0.77498 | 8 |
| 공식 가중치에서 마지막 여섯 층 학습 (`fresh-six`) | 0.76230 | 8 |
| 낮은 학습률로 마지막 네 층 추가 학습 (`extend-four`) | 0.80453 | 9 |
| 문자·명령 토큰 TF-IDF | 0.74271 | 7 |
| 최우수 CodeBERT와 문자·명령 토큰 TF-IDF 순위 결합 | 0.80455 | 8 |

순수 CodeBERT가 검증 AP 0.80에 도달하면 그 모델을 우선한다. `extend-four`는 인코더 학습률 `1.8e-5`, 분류층 학습률 `1e-4`로 8에포크를 학습했고, 검증 AP가 가장 높은 6번째 체크포인트를 선택했다.

| 방법 | 기존 평가셋 AP | 상위 10건의 조사 필요 |
| --- | ---: | ---: |
| 기존 CodeBERT | 0.64600 | 7 |
| 기존 문자 TF-IDF | 0.77492 | 9 |
| `extend-four` | 0.73990 | 9 |

검증셋은 후보와 체크포인트 선택에 사용했다. 평가셋도 이전 실험에서 이미 결과를 확인한 합성 데이터다. 표의 수치는 아이디어톤 실험 결과이며 운영 모델의 승격 판단에는 독립된 로그 평가가 필요하다.

## 재현 절차

저장소 루트에서 `requirements.txt`와 `requirements-codebert-train.txt`를 설치하고, [공식 CodeBERT 가중치와 토크나이저](codebert_shadow.md#입력)를 `base` 경로에 준비한다. 기록된 실행은 CPU 스레드 2개, PyTorch 2.9.0, Transformers 4.46.3, scikit-learn 1.5.1을 사용했다.

```sh
export PYTHONPATH=src HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TOKENIZERS_PARALLELISM=false
base="$PWD/run/base"
run="$(mktemp -d)"
fixture=evaluation/codebert_synthetic_demo_v2

python -m aegis_on.codebert_data prepare --fixture --events "$fixture/events.jsonl" \
  --labels "$fixture/labels.jsonl" --base "$base" --out "$run/splits"
python -m aegis_on.codebert_data audit --splits "$run/splits"
python -m aegis_on.codebert_train --fixture --epochs 5 --base "$base" \
  --train "$run/splits/train.jsonl" --validation "$run/splits/validation.jsonl" --out "$run/baseline"

for recipe in resume-four fresh-six extend-four; do
  python scripts/codebert_ap_train.py "$recipe" --base "$base" --splits "$run/splits" \
    --baseline "$run/baseline" --out "$run" || exit 1
done
for action in lexical select reference; do
  python scripts/codebert_ap_compare.py "$action" --splits "$run/splits" \
    --baseline "$run/baseline" --out "$run" || exit 1
done
```

저장소에는 [검증 후보 비교](../evaluation/codebert_synthetic_demo_v2/ap_improvement/selection.json), [기존 평가셋 참고 결과](../evaluation/codebert_synthetic_demo_v2/ap_improvement/reference.json), [선택 모델 학습 이력](../evaluation/codebert_synthetic_demo_v2/ap_improvement/selected-training.json)을 보관한다. 모델 가중치와 토크나이저는 실행 시 지정한 로컬 출력 디렉터리에 저장된다.
