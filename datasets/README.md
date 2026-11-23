# Aegis-ON 학습·평가 패키지

이 디렉터리는 Replay 화면의 요약 fixture가 아니라, 검증된 가명화 원본 패키지 두 개를 보존한다. 두 패키지는 서로 다른 manifest와 라벨 권위를 가지므로 하나의 지도학습 데이터셋으로 합치지 않는다.

- `learning_eval_log_package_2026-11-21/` — ARTEX 및 정상 비교의 가명화된 수집 패키지. 사례의 최종 보안 라벨은 제공하지 않는다.
- `agent_framework_eval_intake_2026-11-21/` — 런타임·합성 fixture, AI 인계 manifest, split 계약을 포함한 framework intake 패키지.

각 패키지의 `SHA256SUMS.txt`는 패키지 내부 파일을 그대로 검증한다. 저장소 루트에서 다음과 같이 확인할 수 있다.

```sh
(cd datasets/learning_eval_log_package_2026-11-21 && shasum -a 256 -c SHA256SUMS.txt)
(cd datasets/agent_framework_eval_intake_2026-11-21 && shasum -a 256 -c SHA256SUMS.txt)
```

`agent_framework_eval_intake_2026-11-21/label_manifest.jsonl`과 `training_split_manifest.jsonl`은 AI 담당의 기준 파일이다. 현재 실제 사례는 보안팀 검토 전 또는 텔레메트리 전용이므로 supervised 학습·실운영 평가·침해 통계에 사용할 수 없다. 합성 사례는 `synthetic_demo`로 분리돼 있으며, `confirmed_security_incident`는 반드시 `simulated_confirmed_security_incident` 표시와 함께만 사용한다.

이 저장소에는 ZIP을 만들거나 포함하지 않는다. HexStrike는 `blocked_not_run` 상태를 유지하며, 패키지의 정책 fixture는 실제 실행 관측이 아니다.
