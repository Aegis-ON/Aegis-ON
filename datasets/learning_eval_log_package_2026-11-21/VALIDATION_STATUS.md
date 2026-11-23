# 검증 상태

## 이번에 확인한 항목

- 공유 패키지의 JSON 파일은 모두 파싱됐고, `SHA256SUMS.txt`의 무결성 검증을 통과했다.
- Aegis-ON 작업본 `fix/windows-sysmon-collector`의 전체 회귀는 `PYTHONPATH=src python -m unittest discover -s tests -v`로 다시 실행했다. 결과는 **255 passed, 4 skipped**다. 기본 선택형 실모델 테스트는 의도적으로 건너뛴다.
- 보존된 모델의 여섯 파일 해시를 매니페스트와 대조한 뒤, 명시적 통합 테스트를 실행했다. 실제 CPU 로드·warmup·`whoami /groups` 추론·빈 명령·과다 길이 입력 처리가 모두 통과했다. 이것은 **현재 macOS 작업 환경의 모델 검증**이며 Windows에서 모델을 직접 실행했다는 증거는 아니다.
- 과거 Windows 격리 Sandbox 시험에서는 저장 커서 11보다 남은 가장 오래된 이벤트가 1537인 롤오버 조건에서 수집기가 중지하고 커서를 보존하는 것을 확인했다. 원래 Windows 이벤트 로그를 삭제하지 않은 안전 실패 시험이다.
- `curl --version`만의 정상 버전 확인을 도구 전송으로 경보하지 않도록 좁은 규칙 수정이 적용돼 있다. 현재 확인한 커밋은 `78c67c21e17f190adf83ca87368ebbddb925b861`이다.
- Windows 원본 `Microsoft-Windows-Sysmon/Operational`에서 세 사례의 5분 구간을 직접 조회했다. ARTEX 구간(`11:12:00Z`–`11:17:00Z`), 정상 후보 구간(`09:47:00Z`–`09:52:00Z`), 승인된 정상 비교 구간(`16:45:00Z`–`16:50:00Z`) 모두 Event ID 1·3은 각각 **0건**이었다. 결과는 패키지의 각 `sysmon_event_{1,3}.json`에 반영했다. 이 0건 결과는 활성 규칙 범위 한계 때문에 프로세스 부재·무해·침해 부재의 증거가 아니다.
- 현재 Sysmon 15.22 서비스는 실행 중이며 `AUTO_START`로 구성돼 있다. 활성 규칙은 `testCurl.exe`에만 Process Create와 Network Connect를 포함하므로, 별도 Docker 컨테이너에서 나온 ARTEX 웹 요청이 이 Windows Sysmon 필터에 남지 않은 원인을 설명한다.
- Event ID 255의 원시 메시지를 재조회했다. `GetConfigurationOptions`에서 서비스 구성을 열지 못했고 마지막 오류가 “미디어가 쓰기 금지되어 있습니다”로 기록됐다. 현재는 구성 조회와 서비스 실행이 정상인 점에서, 당시의 일시적 부팅·저장장치 쓰기 보호 상태로 분류한다.
- private BERT 모델 압축본을 Windows 호스트로 전송했고, 전송 전·후 SHA-256을 대조했다. 추출된 `model.safetensors` 해시는 매니페스트와 일치한다. Windows에서 PyTorch 2.7.0·Transformers 4.41.2·Safetensors 0.5.3을 사용해 로컬 파일만 참조하는 직접 추론을 실행했다.
- Windows를 실제 재부팅한 뒤 Sysmon64 서비스가 `AUTO_START` 구성으로 `RUNNING` 상태가 되었고, Event ID 4에 `State: Started`(UTC `2026-11-21T07:48:04.162Z`)가 기록된 것을 확인했다. Sysmon 15.22와 기존 설정 파일도 재부팅 뒤 정상으로 조회됐다.
- PR #23은 Draft 해제 뒤 merge commit `b279596ffaf0fecb05bd0acd3115a799ae818fae`로 `main`에 병합됐다.

## 완료 범위와 해석 제한

- 위 검증은 격리 실습 환경과 Windows 호스트에서 실제 실행한 결과다. 모델의 낮은 차이의 점수는 최종 보안 라벨이 아니며, 보안팀의 타임라인 대조가 계속 필요하다.
- 현재 Sysmon 규칙이 `testCurl.exe`만 포함한다는 관측 범위 한계는 남아 있다. 컨테이너 기반 프레임워크의 실제 프로세스·네트워크 상관분석을 위해서는 별도의 컨테이너 경계 수집 보강이 필요하다.
