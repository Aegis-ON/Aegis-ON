# 원천 로그 인계 확인

원본 사례 패키지와 프레임워크 인계 패키지를 접근이 제한된 경로에 준비한 뒤 저장소 루트에서 파일 목록을 만든다.

```bash
PYTHONPATH=src python -m aegis_on.case_intake_inventory \
  --original /private/path/original-package \
  --intake /private/path/intake-package > /private/path/case-intake-inventory.json
```

`--original`은 `manifest.json`과 `cases/`가 있는 디렉터리다. `--intake`는 `runtime_cases/`, `synthetic_cases/`와 인계 파일 4개가 있는 디렉터리다.

출력에는 패키지 기준 상대 경로, 파일 크기, SHA-256과 읽지 못한 항목이 담긴다. 필수 자료가 없거나 읽을 수 없으면 종료 코드 1을 반환한다. 인계자가 기록한 체크섬이 있으면 계산 결과와 대조한다. 출력의 파일명도 내부 정보를 담을 수 있어 원본과 같은 접근 제한을 적용한다.

파일 목록을 확인한 뒤 인계 자료 규격을 읽고 두 목록을 `case_id`로 대조한다. 보안팀의 라벨 검토 기록과 학습 사용 조건을 확인한 후 분할 대상을 선정한다.
