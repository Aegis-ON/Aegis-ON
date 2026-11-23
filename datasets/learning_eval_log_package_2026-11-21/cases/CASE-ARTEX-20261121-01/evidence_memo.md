# 조사 메모 — CASE-ARTEX-20261121-01

## 근거와 범위

- 통제된 실습 범위에만 가상 HTTP 서비스를 등록한 뒤, `GET /`, `GET /health`, `GET /login`, `GET /api/status` 순으로 HTTP 200 접근 4건이 남았다.
- 각 행의 UTC 시각과 서비스 기록 순서는 `web_and_auth_logs.json` 및 `timeline.json`에 보존했다. 원래 출발지·요청 ID는 공유본에서 안정적인 가명으로 치환했다.
- 이 증거만으로 공격 성공, 인증 성공, 취약점 존재를 판단하지 않는다. `/login`은 단순 GET 접근이다.

## 조사할 Windows 이벤트

| Event ID | 이유 | 이 묶음의 상태 |
| --- | --- | --- |
| 1 — Process Create | 실행 이미지, 부모 프로세스, 명령줄, ProcessGuid로 실행 연쇄를 웹 시각과 상관분석할 수 있음 | Windows 원본 5분 구간 직접 조회 결과 0건 |
| 3 — Network Connect | 관련 프로세스의 연결과 주소·포트를 ProcessGuid로 결합할 수 있음 | Windows 원본 5분 구간 직접 조회 결과 0건 |

Sysmon Event ID 3은 기본적으로 비활성화될 수 있으므로, 파일이 비어 있다는 사실을 “네트워크 연결이 없었다”는 결론으로 쓰면 안 된다. Microsoft의 [Sysmon 이벤트 문서](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)는 Event ID 1을 프로세스 생성, Event ID 3을 프로세스와 연결되는 TCP/UDP 연결로 설명한다.

## 후속 수집 원칙

1. UTC `11:12:00Z`부터 `11:17:00Z`까지 Event ID 1과 3을 원본에서 직접 조회했고 각 0건임을 확인했다.
2. 활성 규칙이 `testCurl.exe`만 포함하고 웹 요청이 별도 Docker 컨테이너에서 발생한 것을 함께 보존했다. 따라서 0건을 무행위 증거로 해석하지 않는다.
3. 이벤트 앞뒤 레코드와 Sysmon Event ID 4·16·255을 별도 보존해 서비스·설정·오류 상태를 대조한다.
4. 보안팀이 원본과 실행 기록을 대조한 뒤에만 최종 라벨을 붙인다.
