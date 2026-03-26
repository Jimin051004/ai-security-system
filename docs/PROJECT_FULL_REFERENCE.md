# 프로젝트 전체 참조서 (폴더·파일·기능·미이행 점검)

이 문서는 **저장소 루트 기준**으로 **모든 폴더와 파일**을 **제목·역할·내용** 수준에서 상세히 정리한 것입니다.  
마지막에 **대화 중 사용자 요청 대비 “안 되었거나 부분만 된 것”** 을 제가 점검해 적어 두었습니다.

---

## 목차

1. [프로젝트 한눈에](#1-프로젝트-한눈에)
2. [디렉터리 트리](#2-디렉터리-트리)
3. [폴더별 설명](#3-폴더별-설명)
4. [파일별 상세 설명](#4-파일별-상세-설명)
5. [데이터·요청 흐름](#5-데이터요청-흐름)
6. `[owasp/a05.py` 요약 (인젝션 규칙)](#6-owaspa05py-요약-인젝션-규칙)
7. [사용자 요구 사항 대비 이행·미이행 점검](#7-사용자-요구-사항-대비-이행미이행-점검)
8. [기술적 한계 (HTTP·SPA)](#8-기술적-한계-httpspa)
9. [다른 문서와의 관계](#9-다른-문서와의-관계)

---

## 1. 프로젝트 한눈에


| 항목        | 내용                                                                       |
| --------- | ------------------------------------------------------------------------ |
| **이름**    | AI Security System (저장소: `ai-security-system`)                           |
| **핵심**    | FastAPI **리버스 프록시** + **WAF(요청 스캔)** + 업스트림(주로 **OWASP Juice Shop**)     |
| **OWASP** | Top 10 **2025** 모듈 `a01`~`a10`— **실제 탐지 규칙이 채워진 것은 주로`a05`(Injection)**  |
| **UI**    | `/__waf/dashboard` 대시보드, 차단 시 `waf_blocked.html` (+ `alert`) 또는 JSON 403 |
| **런타임**   | Python 3, `uvicorn main:app`, 환경 변수 `.env` / `.env.example`              |


---

## 2. 디렉터리 트리

```
졸업작품/  (프로젝트 루트)
├── .cursor/
│   └── rules/                    # Cursor 에디터용 규칙
├── .env.example                  # 환경 변수 예시 (복사해 .env)
├── .gitignore
├── README.md                     # 루트 설명·실행 방법
├── FETCH_HEAD                    # Git fetch 부산물(보통 커밋 대상 아님)
├── detector.py                   # OWASP 모듈 일괄 실행·심각도 필터
├── docker-compose.yml            # Juice Shop 컨테이너
├── main.py                       # FastAPI 앱·프록시·WAF 게이트·대시보드 라우트
├── request_snapshot.py           # Starlette Request → RequestContext
├── requirements.txt
├── requirements-dev.txt
├── traffic_log.py                # 프록시 통과/차단 로그 링 버퍼
├── docs/                         # 기획·테스트·네트워크·본 참조서 등
├── owasp/                        # OWASP Top10 모듈 (a01~a10)
├── static/waf/                   # 대시보드·차단 페이지 정적 파일
├── templates/                    # Jinja2 HTML
└── verification/                 # 자동 검증 스위트 (pytest, pytest.ini)
```

---

## 3. 폴더별 설명

### 3.1 `.cursor/rules/`

**기능:** Cursor AI가 이 저장소에서 일할 때 따를 **워크스페이스 규칙**입니다.


| 파일                   | 내용                                |
| -------------------- | --------------------------------- |
| `github-sync.mdc`    | 커밋·푸시 전 **사용자 동의** 요청, 메시지 규칙 등   |
| `change-summary.mdc` | 작업 후 **변경 요약을 한국어로** 응답에 포함하라는 지침 |


---

### 3.2 `docs/`

**기능:** 사람이 읽는 **설계·실행·테스트·참조** 문서 모음.


| 파일                              | 제목·역할 (요약)                                  |
| ------------------------------- | ------------------------------------------- |
| `README.md`                     | `docs/` 안 문서 목록 테이블                         |
| `PLAN.md`                       | 졸업작품/프로젝트 **전체 계획** (WAF·LLM·OWASP)         |
| `IMPLEMENTATION_ROADMAP.md`     | **구현 순서** 로드맵                               |
| `JUICE_SHOP_NETWORK_SETUP.md`   | Docker·LAN·포트 **Juice Shop + 프록시** 네트워크 가이드 |
| `TESTING.md`                    | pytest, curl, 대시보드 URL 등 **테스트 방법**         |
| `OWASP_TOP10_2025.md`           | OWASP Top 10 2025 **정리·프로젝트 연계** (긴 문서)     |
| `OWASP_TOP10_2025_Guide.md`     | 위와 유사 **가이드** 성격 긴 문서                       |
| `**PROJECT_FULL_REFERENCE.md`** | **본 문서** — 전체 폴더/파일 설명 + 미이행 점검             |


---

### 3.3 `owasp/`

**기능:** OWASP Top 10 **2025** 항목별 **요청 스캔 모듈**.  
`detector.py`가 `MODULES` 순서대로 `scan(ctx)` 호출.

- `**a05.py`만** SQL/XSS 등 **풍부한 시그니처**가 있음.
- `**a01~~a04`, `a06~~a10`** 은 현재 **스켈레톤**(`clean_result` 등)으로 **탐지 0건**에 가깝게 동작.


| 파일                  | 역할                                                          |
| ------------------- | ----------------------------------------------------------- |
| `__init__.py`       | `MODULES` 튜플, `OWASPModule` dataclass, export               |
| `types.py`          | `RequestContext`, `Finding`, `ModuleScanResult`, `Severity` |
| `a01.py` ~ `a10.py` | 항목별 `scan` 진입점                                              |


---

### 3.4 `static/waf/`

**기능:** 브라우저에 직접 제공되는 **CSS/JS** (`/__waf/static/...`).

```
static/waf/
├── css/
│   ├── dashboard.css      # 대시보드 레이아웃·카드·테이블
│   └── waf_blocked.css    # 차단 전용 페이지 스타일
└── js/
    ├── dashboard.js       # 요약·트래픽·클라이언트·모듈·탐지 표 갱신
    └── waf_blocked.js     # #waf-block-boot JSON 읽어 alert()
```

---

### 3.5 `templates/`

**기능:** Jinja2 **HTML** (`main.py`의 `jinja2.Environment`).


| 파일                 | 역할                                        |
| ------------------ | ----------------------------------------- |
| `dashboard.html`   | WAF 대시보드 (업스트림·로그·탐지·차단 상세 표 등)           |
| `waf_blocked.html` | 403 차단 시 **제목·부제·항목 목록·alert용 boot JSON** |


---

### 3.6 `verification/`

**기능:** **pytest** 자동 검증 스위트. 루트 `pytest.ini`의 `testpaths = verification` 으로 수집한다. `conftest.py`에서 `UPSTREAM_URL`, `WAF_*` 기본값 설정.

---

## 4. 파일별 상세 설명

### 4.1 루트 파일


| 파일                         | 제목·기능          | 내용(세부)                                                                                                                                                                                                                                                                                                                |
| -------------------------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `**main.py`**              | **애플리케이션 본체**  | FastAPI `app`: 업스트림 **프록시**, `request_to_context` 후 `scan_request`, `WAF_BLOCK_MIN_SEVERITY` 이상이면 **403** (HTML `waf_blocked` 또는 JSON). `_prefer_waf_block_html`로 형식 분기. 업스트림 응답 **본문·Location** 의 절대 URL을 클라이언트가 접속한 호스트로 **리라이트**. `/__waf/dashboard`, `/__waf/api/*`, `traffic_log.record`, `mount /__waf/static`. |
| `**detector.py`**          | **모듈 오케스트레이션** | `scan_request`: `MODULES` 전부 `await scan(ctx)`. `all_findings`, `findings_at_or_above_severity`, `parse_severity`.                                                                                                                                                                                                    |
| `**request_snapshot.py`**  | **요청 스냅샷**     | `request.body()` 한 번 읽어 앞 `body_preview_max` 바이트만 UTF-8 디코드, `RequestContext` 생성.                                                                                                                                                                                                                                     |
| `**traffic_log.py`**       | **메모리 로그**     | 최대 200건 `deque`, IP별 집계. `should_log_path`로 `/__waf`, `/__proxy` 제외. 차단 시 `block_findings` 튜플 저장.                                                                                                                                                                                                                     |
| `**docker-compose.yml`**   | **Juice Shop** | `bkimminich/juice-shop`, 호스트 `3001:3000`.                                                                                                                                                                                                                                                                             |
| `**requirements.txt`**     | 런타임 의존성        | FastAPI, httpx, jinja2 등                                                                                                                                                                                                                                                                                              |
| `**requirements-dev.txt**` | 개발 의존성         | `requirements.txt` + pytest                                                                                                                                                                                                                                                                                           |
| `**.env.example**`         | 환경 변수 샘플       | `UPSTREAM_URL`, `WAF_BLOCK_MIN_SEVERITY`, `WAF_ENABLED`, `WAF_BODY_PREVIEW_MAX` 안내                                                                                                                                                                                                                                    |
| `**.gitignore**`           | Git 제외 목록      | venv, `.env`, `__pycache__` 등                                                                                                                                                                                                                                                                                         |
| `**README.md**`            | 프로젝트 소개        | 설치, uvicorn, 대시보드 URL, 문서 링크                                                                                                                                                                                                                                                                                          |
| `**FETCH_HEAD**`           | Git 내부 파일      | 로컬에 남은 경우 **실수로 커밋하지 말 것** 권장                                                                                                                                                                                                                                                                                         |


---

### 4.2 `owasp/` 파일


| 파일                      | 제목·기능                         | 내용(세부)                                                                                                                                                                                                                    |
| ----------------------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `**types.py`**          | 공통 타입                         | `RequestContext`(method, path, query_string, headers, body_preview), `Finding`(rule_id, evidence, severity, location), `ModuleScanResult`, `clean_result()` 헬퍼                                                            |
| `**a01.py**`            | A01 Broken Access Control     | 스켈레톤 — 실질 규칙 거의 없음                                                                                                                                                                                                        |
| `**a02.py**`            | A02 Security Misconfiguration | 스켈레톤                                                                                                                                                                                                                      |
| `**a03.py**`            | A03 …                         | 스켈레톤                                                                                                                                                                                                                      |
| `**a04.py**`            | A04 Cryptographic Failures    | 스켈레톤                                                                                                                                                                                                                      |
| `**a05.py**`            | **A05 Injection**             | **SQL, OS CMD, XSS, LDAP, XPath, EL/SSTI, CRLF** 정규식 규칙, URL 디코드 계층, JSON/폼/쿼리/헤더 스캔, `_deduplicate`, `async scan`. 파일 하단 `**make_block_html`** 등은 **과거용 인라인 HTML** — `**main.py`는 현재 미사용**(Jinja `waf_blocked.html` 사용). |
| `**a06.py` ~ `a10.py`** | 각 OWASP 항목                    | 스켈레톤 수준                                                                                                                                                                                                                   |


---

### 4.3 `verification/` 파일


| 파일                   | 검증 내용                                                       |
| -------------------- | ----------------------------------------------------------- |
| `conftest.py`        | `UPSTREAM_URL`, `WAF_ENABLED`, `WAF_BLOCK_MIN_SEVERITY` 기본값 |
| `app_health.py`      | 앱 헬스/기본 응답                                                  |
| `waf_dashboard.py`     | 대시보드 HTML, API, 차단 시 traffic `block_findings`               |
| `detector_policy.py`   | 심각도 파싱·필터·`all_findings`                                    |
| `proxy_rewrite.py`     | 업스트림 URL → 공개 호스트 치환, 응답 헤더 형식                              |
| `traffic_recorder.py`  | 기록·스냅샷·`/__waf` 미기록                                         |
| `waf_block_page.py`    | 403 시 JSON vs HTML `Accept` 분기, Juice Shop 스타일 Accept       |
| `a05_login_sqli.py`    | JSON 로그인 바디 `admin@juice-sh.op' -` 등 **A05-SQL-010**        |


---

## 5. 데이터·요청 흐름

1. 클라이언트 → `**main.py`** 프록시 라우트 (`/` 또는 `/{path}`).
2. `await request.body()` (한 번) → `**request_to_context**` → `**RequestContext**`.
3. `**detector.scan_request**` → `owasp` 각 모듈 `**scan(ctx)**`.
4. `**all_findings**` + `**findings_at_or_above_severity(min)**` → 차단 목록.
5. 차단 시: `**traffic_log.record(..., block_findings=...)**` + **403** (`HTMLResponse` 또는 `JSONResponse`).
6. 비차단 시: **httpx**로 `UPSTREAM_URL`에 동일 메서드/경로/쿼리/본문 **전달** → 응답 가공 후 반환.

---

## 6. `owasp/a05.py` 요약 (인젝션 규칙)

(전체 표는 길어서 **규칙 ID 접두사**로 묶어 요약합니다. 상세 패턴은 소스 주석·정규식 참고.)


| 계열      | 접두사                      | 예시 유형                                                             |
| ------- | ------------------------ | ----------------------------------------------------------------- |
| SQL     | `A05-SQL-*`              | OR 1=1, UNION, 주석, time-based, stacked query, `0x…`, 따옴표+`-` 로그인형 |
| OS 명령   | `A05-CMD-*`              | `;cat`, `$()`, 백틱, /etc/passwd, curl 외부 전송                        |
| XSS     | `A05-XSS-*`              | `<script`, `javascript:`, `onerror`, `<iframe`, `eval(` 등         |
| LDAP    | `A05-LDAP-*`             | 필터 조작, `*)(`, `uid=*`                                             |
| XPath   | `A05-XPATH-*`            | `' or 'x'='y'`, `//`, blind 함수                                    |
| EL/SSTI | `A05-EL-*`, `A05-SSTI-*` | `${}`, `#{}`, `%{}`, `{{}}`, `{% %}`                              |
| CRLF    | `A05-CRLF-*`             | `%0d%0a`, 헤더 삽입 시도                                                |


**한계:** URL `**#` 이후**는 HTTP에 없음 → **해시 라우팅 검색창 XSS** 등은 **스캔 불가**.

---

## 7. 사용자 요구 사항 대비 이행·미이행 점검

대화에서 나온 요청을 기준으로 **제가 코드/문서 상태를 보며** 정리했습니다.

### 7.1 이행된 것 (대체로 완료)


| 요청 요지                                                                             | 상태  | 비고                                                          |
| --------------------------------------------------------------------------------- | --- | ----------------------------------------------------------- |
| WAF **스캔 시험 UI** 제거, **실제 트래픽** 기준 **탐지·차단 표**                                    | ✅   | 대시보드 `탐지·차단 상세`, `traffic_log.block_findings`               |
| 차단 시 **OWASP·유형·위치** 등 상세                                                         | ✅   | JSON `findings` + HTML 표 + `main`의 `_finding_enriched_dict` |
| `**a05.py`에 탐지 로직** (main에 별도 스캔 API 두지 않기)                                       | ✅   | `POST /__waf/api/scan/a05` 제거된 상태 유지                        |
| 커밋은 **허락 후**                                                                      | ✅   | `.cursor/rules/github-sync.mdc`                             |
| 작업 후 **변경 설명**                                                                    | ✅   | `.cursor/rules/change-summary.mdc`                          |
| 차단 **HTML + alert**, **취약점 유형 문구** (예: SQL Injection)                             | ✅   | `waf_blocked.html`, `_waf_blocked_html_response`            |
| **CSS/JS 분리** (`waf_blocked`)                                                     | ✅   | `static/waf/css/waf_blocked.css`, `js/waf_blocked.js`       |
| 로그인형 `**admin@juice-sh.op' -`** 등 **A05-SQL-010**                                 | ✅   | `a05.py` + `test_a05_login_sqli.py`                         |
| **Juice Shop 스타일 Accept** (`application/json, text/plain, */*`) 에도 **HTML 차단 본문** | ✅   | `_prefer_waf_block_html` 완화 + 테스트                           |
| **전체 참조 MD** (본 문서)                                                               | ✅   | 지금 읽는 파일                                                    |


### 7.2 부분 이행·조건부 (기대와 다를 수 있음)


| 요청·기대                                  | 상태              | 이유                                                                                                      |
| -------------------------------------- | --------------- | ------------------------------------------------------------------------------------------------------- |
| 로그인 버튼 후 **화면에 반드시 차단 페이지가 “뜸”**       | ⚠️ **부분**       | XHR 응답으로 **HTML 본문은 올 수 있으나**, Angular는 **전체 문서를 자동 교체하지 않음**. Network 탭에서 응답 확인 또는 **주소창 GET** 시연이 확실. |
| `**#/search?q=...` XSS/SQLi 도 WAF 차단** | ⚠️ **불가(HTTP)** | **해시는 서버로 전송되지 않음** — WAF가 문자열을 볼 수 없음. **브라우저·HTTP 스펙 한계**이지 버그가 아님.                                   |
| **“나머지 모든 인젝션도 XSS처럼 화면에 보인다”**        | ⚠️ **동일 조건**    | 인젝션 **종류**가 아니라 **요청 형식(GET 문서 vs XHR)** 과 **Accept** 가 표시를 좌우함.                                        |


### 7.3 이행되지 않았거나 저장소에 없는 것


| 항목                                         | 상태      | 비고                                                                                           |
| ------------------------------------------ | ------- | -------------------------------------------------------------------------------------------- |
| `**make_block_html` 및 관련 인라인 CSS HTML** 제거 | ❌ 미정리   | `a05.py` 하단 **레거시**. `main` 미사용 — **삭제해도 동작 무관**(다른 import 없을 때).                            |
| **A01~~A04, A06~~A10** 실제 탐지 규칙 채우기        | ❌ 미구현   | 계획서(`PLAN.md`) 수준; 현재 **a05 중심**.                                                            |
| **응답 스캔** (A02/A04/A10 등)                  | ❌ 미구현   | 로드맵에 언급될 수 있으나 **현재는 요청만** 스캔.                                                               |
| **LLM(Mistral 등) 연동**                      | ❌ 코드 없음 | `README.md` 비전에 가깝고 **본 레포 핵심 코드에 없음**.                                                      |
| **단일 `WAF_A05_INJECTION_GUIDE.md`만 별도 유지** | ⚠️      | 이전에 쓴 적 있으나 **현재 `docs/` 목록에는 없을 수 있음** — **본 문서 6절에 요약 통합**. 필요 시 같은 내용을 분리 파일로 다시 만들 수 있음. |


### 7.4 정리

- **“안 된다”고 느끼는 경우** 많은 수가 `**#` 해시**, **SPA XHR**, **브라우저가 HTML 응답을 페이지로 그리지 않는 구조** 때문입니다.
- **코드로 막을 수 있는 부분**(서버로 올라오는 path/query/body/header)은 `**a05` + `main` 게이트**로 처리 중입니다.

---

## 8. 기술적 한계 (HTTP·SPA)

1. **Fragment (`#...`)**
  서버·프록시·WAF **절대 수신 안 함** → 해시 안의 검색어·XSS **탐지 불가**.
2. **본문 크기**
  `body_preview` 상한 초과분은 **미스캔** 가능.
3. **정규식 WAF**
  **오탐·미탐** 가능. 교육/데모용에 가깝고 상용 WAF 대체는 아님.
4. **403 HTML + SPA**
  `fetch`/`HttpClient`는 응답을 **문서로 렌더하지 않음**.

---

## 9. 다른 문서와의 관계


| 문서                                   | 용도                         |
| ------------------------------------ | -------------------------- |
| `README.md`                          | 빠른 시작                      |
| `docs/PLAN.md`                       | 비전·범위                      |
| `docs/TESTING.md`                    | 검증 방법                      |
| `**docs/PROJECT_FULL_REFERENCE.md`** | **본 문서 — 구조 전수 + 요구 대비 갭** |


---

*문서 생성 시점: 저장소 파일 목록을 기준으로 작성. 이후 파일이 늘거나 줄면 이 문서도 같이 갱신하는 것이 좋습니다.*