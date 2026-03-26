# 구현 로드맵 (다음 작업 계획)

전체 비전·성공 기준은 [PLAN.md](./PLAN.md)를 따른다. 여기서는 **현재 코드 기준으로 무엇을 어떤 순서로 만들지**만 정리한다.

---

## 현재까지 된 것

- FastAPI 리버스 프록시 (`main.py`) → **`UPSTREAM_URL`** 로 지정한 **임의 업스트림**으로 HTTP 전달 (Juice Shop 전용 로직 없음)
- **1단계 적용됨:** 요청 → `request_snapshot.request_to_context` → `detector.scan_request` → `WAF_BLOCK_MIN_SEVERITY` 이상이면 **403 JSON**, 아니면 업스트림 프록시
- 환경 변수: `WAF_ENABLED`, `WAF_BLOCK_MIN_SEVERITY`, `WAF_BODY_PREVIEW_MAX` (`.env.example` 참고)
- OWASP Top 10:2025용 모듈 10개 **파일·등록 구조** (`owasp/`, `MODULES`)
- `detector.py`: `scan_request`, `all_findings`, **차단 임계** `findings_at_or_above_severity`, `parse_severity`
- 각 모듈은 대부분 **스켈레톤**(실제 패턴 탐지는 2단계에서) → 지금은 탐지가 거의 없어 대부분 통과
- Docker·문서: `docs/JUICE_SHOP_NETWORK_SETUP.md` 등

---

## 1단계: 요청 파이프라인에 탐지·차단 끼워 넣기 — **구현 완료**

### 쉽게 말하면

- 브라우저 → **문지기(WAF)**가 요청을 잠깐 봄 → 정책상 차단이면 **403**, 아니면 **`UPSTREAM_URL`** 업스트림으로 프록시.

### 코드 흐름 (반영된 위치)

1. `request_snapshot.py`: `Request` → **`RequestContext`** (method, path, query, headers, body 프리뷰)
2. `detector.scan_request` → `all_findings`
3. `findings_at_or_above_severity(..., WAF_BLOCK_MIN_SEVERITY)` → 있으면 **403** JSON (`blocked`, `findings`, …), 없으면 **`_forward`**

**업스트림 교체:** `UPSTREAM_URL` 만 바꾸면 동일 WAF가 다른 오픈소스/사이트에 적용된다.

이 구성은 [PLAN.md](./PLAN.md) §12의 *「탐지·차단이 하나의 요청 파이프라인에서 설명 가능」*에 맞는 첫 단계다.

---

## 2단계: 최소 한 모듈은 실제 탐지 (데모)

- **`owasp/a05.py` (Injection)** 에 SQLi 등 짧은 시그니처·패턴을 넣는 것부터 권장 (Juice Shop과 연계하기 쉬움).
- 이후 **요청만 보면 되는** 모듈부터 채움 (예: A01 경로, A02 민감 경로 노출 휴리스틱).

---

## 3단계: 기록(로그)

- SQLite 등으로 이벤트 저장 ([PLAN.md](./PLAN.md) §6 스키마 초안 참고).
- 필드 예: 시각, 경로, OWASP 태그, 규칙 ID, 차단 여부.
- 탐지·차단 시 **감사용으로 최소 한 줄 저장**이 목표.

---

## 4단계: PLAN 후반 기능

- **LLM 2차 판정** (환경 변수로 on/off).
- **대응**: 차단·고위험 시 짧은 리미디에이션 텍스트(템플릿 또는 LLM).
- **API + 최소 웹 UI**: 이벤트 조회, 요약 통계.

---

## 5단계: 문서·검증

- 루트 `README.md`에 “프록시 + 탐지 + DB” 실행 순서 보강.
- [PLAN.md](./PLAN.md) §12 성공 기준 체크박스를 구현 진행에 맞게 갱신.
- [PLAN.md](./PLAN.md) §11 검증 시나리오로 수동·자동 테스트.

---

## 한 줄 요약

**`main.py`에 detector 연결 → 차단 정칙 → (다음으로) A05 시그니처 → SQLite 로그** 순으로 가면 졸업작품 범위에 맞는 골격이 빨리 잡힌다.

---

## 변경 이력

| 날짜 | 내용 |
|------|------|
| 2026-03-26 | 초안 — 파이프라인·모듈·로그·LLM·UI 순서로 정리 |
| 2026-03-26 | 1단계 구현 반영 — `request_snapshot`·`main` WAF 게이트·`UPSTREAM_URL` 범용 |
