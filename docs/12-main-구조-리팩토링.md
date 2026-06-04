# 12. main.py 구조 리팩토링 설계

## 1. 현재 구조

`main.py`는 프록시 서버 진입점이면서 아래 책임을 함께 가진다.

| 번호 | 책임 | 현재 위치 |
|---|---|---|
| 1-1 | 환경 변수와 사이트 설정 | `main.py` 상단 |
| 1-2 | 중앙 대시보드 ingest | `_send_central_log`, `_record_proxy_event` |
| 1-3 | 업스트림 프록시 forwarding | `_forward`, `_build_proxied_upstream_response` |
| 1-4 | WAF 스캔 gate | `_run_waf_gate` |
| 1-5 | 차단 응답 생성 | `_blocking_payload_dict`, `_waf_blocked_html_response` |
| 1-6 | health/API/fragment scan | FastAPI route |
| 1-7 | worker console 연결 | `attach_worker_console` |

## 2. 이번 리팩토링 범위

이번 변경은 회귀 위험을 줄이기 위해 차단 응답 생성 책임만 분리한다.

| 번호 | 분리 대상 | 신규 파일 |
|---|---|---|
| 2-1 | Finding enrichment | `waf_block_response.py` |
| 2-2 | API payload 생성 | `waf_block_response.py` |
| 2-3 | HTML/JSON 선호 판단 | `waf_block_response.py` |
| 2-4 | 차단 페이지 headline/alert 생성 | `waf_block_response.py` |

## 3. 목표 구조

```text
main.py
  - 요청 수신
  - WAF gate 실행
  - 차단 시 waf_block_response 호출
  - 통과 시 upstream forwarding

waf_block_response.py
  - rule_id → 공격 유형 라벨
  - Finding → dashboard/block page dict
  - block payload 생성
  - HTML 차단 페이지 렌더링
```

## 4. 변경하지 않는 것

| 번호 | 항목 | 이유 |
|---|---|---|
| 4-1 | 프록시 forwarding | 네트워크 경로 회귀 위험 최소화 |
| 4-2 | 중앙 ingest | DB/센서 연동 회귀 위험 최소화 |
| 4-3 | WAF 정책 판단 | 기존 테스트 보존 |
| 4-4 | route URL | 기존 UI/테스트 호환 |

## 5. 테스트 계획

| 번호 | 테스트 | 목적 |
|---|---|---|
| 5-1 | `py_compile` | import 순환/문법 오류 확인 |
| 5-2 | `pytest verification/waf_block_page.py` | 차단 HTML/JSON 응답 유지 |
| 5-3 | `pytest verification/ai_second_pass_test.py` | AI 차단 payload 유지 |
| 5-4 | 전체 `pytest` | 기존 기능 회귀 확인 |

## 6. 위험과 대응

| 번호 | 위험 | 대응 |
|---|---|---|
| 6-1 | import 순환 | 신규 모듈은 `main.py`를 import하지 않음 |
| 6-2 | 차단 페이지 렌더링 깨짐 | Jinja env를 인자로 전달 |
| 6-3 | rule label 차이 | 기존 함수 로직을 그대로 이동 |
| 6-4 | 테스트 실패 | 기능 변경 없이 구조만 이동 |
