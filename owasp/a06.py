"""A06:2025 — Insecure Design (안전하지 않은 설계)

비즈니스 로직의 구조적 보안 결함을 탐지한다.
코드 버그가 아닌, 처음부터 보안 제어가 설계에 없는 취약점을 대상으로 한다.

관련 CWE: CWE-269, CWE-434, CWE-522, CWE-602, CWE-657, CWE-799, CWE-841

────────────────────────────────────────────────────────────────────────────────
Juice Shop 검증 시나리오 (사전 검증 완료 — 탐지 O / 정상 요청 false positive 없음)
────────────────────────────────────────────────────────────────────────────────
Rule              | 탐지 내용                            | Juice Shop 호출 예시
──────────────────┼──────────────────────────────────────┼──────────────────────────────────────────
A06-ROLE-001      | isAdmin:true 관리자 권한 직접 주입    | POST /api/Users {"isAdmin":true,...}
A06-ROLE-002      | role:"admin" 역할 필드 직접 변조      | PUT  /api/Users/5 {"role":"admin"}
A06-ROLE-003      | admin:true / userType:admin 기타 패턴 | POST body: {"admin":true}
A06-PRICE-001     | price:0 또는 음수 — 가격 변조         | PUT  /api/BasketItems/1 {"price":0}
A06-PRICE-002     | amount/total/cost:0 — 결제 금액 변조  | POST /api/Orders {"total":0}
A06-PRICE-003     | discount:100 이상 — 할인율 변조       | POST /api/Orders {"discount":100}
A06-MASS-001      | 보호 필드 주입 (totpSecret 등)        | PUT  /api/Users/1 {"totpSecret":"..."}
A06-MASS-002      | 계정 상태 필드 직접 변조 (isActive 등)| POST /api/Users {"isActive":true}
A06-ADMIN-001     | 전체 유저 목록 직접 조회              | GET  /api/Users
A06-ADMIN-002     | FTP 디렉토리 직접 접근                | GET  /ftp
A06-ADMIN-003     | 보안 질문 목록 노출                   | GET  /api/SecurityQuestions
A06-ADMIN-004     | API 문서·메트릭 노출 경로 접근        | GET  /api-docs /swagger /metrics
A06-STEP-001      | 주문 추적 직접 접근 (워크플로우 우회)  | GET  /rest/track-order/{id}
A06-RATE-001      | 동일 IP 단시간 과다 요청 (Rate Limit) | /rest/user/login × 10회/60초
────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import math
import re
import time
import urllib.parse
from collections import Counter, defaultdict
from dataclasses import dataclass

from owasp.types import Finding, ModuleScanResult, RequestContext, Severity


# ── 모듈 메타데이터 ──────────────────────────────────────────────────────────

MODULE_ID = "a06"
OWASP_ID  = "A06:2025"
TITLE     = "Insecure Design"


# ── Shannon Entropy & 점수 계산 ──────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _entropy_bonus(s: str) -> float:
    e = _shannon_entropy(s)
    if e >= 4.5:
        return 0.5
    if e >= 3.5:
        return 0.25
    return 0.0


def _score_to_severity(score: float) -> Severity:
    if score >= 3.5:
        return Severity.CRITICAL
    if score >= 2.5:
        return Severity.HIGH
    if score >= 1.5:
        return Severity.MEDIUM
    return Severity.LOW


# ── Rate Limit 인메모리 추적 ─────────────────────────────────────────────────
# {ip|path_pattern: [timestamp, ...]}
_rate_store: dict[str, list[float]] = defaultdict(list)

# (path 정규식, 윈도우(초), 최대 허용 횟수, base_score)
_RATE_RULES: list[tuple[re.Pattern[str], int, int, float]] = [
    (re.compile(r"^/rest/user/login$",            re.IGNORECASE), 60,  10, 2.5),
    (re.compile(r"^/rest/user/forgot-password$",  re.IGNORECASE), 300,  5, 2.5),
    (re.compile(r"^/api/Users$",                  re.IGNORECASE), 60,   5, 2.0),
    (re.compile(r"^/api/Feedbacks$",              re.IGNORECASE), 60,   5, 1.5),
    (re.compile(r"^/rest/products/reviews",       re.IGNORECASE), 60,  10, 1.5),
]


def _get_client_ip(headers: dict[str, str]) -> str:
    xff = headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return headers.get("x-real-ip", "unknown")


def _check_rate_limit(ctx: RequestContext) -> Finding | None:
    ip   = _get_client_ip(ctx.headers)
    path = ctx.path
    now  = time.monotonic()

    for pattern, window, max_req, base_score in _RATE_RULES:
        if not pattern.match(path):
            continue
        key   = f"{ip}|{pattern.pattern}"
        times = _rate_store[key]
        times[:] = [t for t in times if now - t < window]
        times.append(now)
        count = len(times)
        if count <= max_req:
            continue
        excess = count / max_req
        score  = base_score + min(excess - 1.0, 1.5)
        return Finding(
            rule_id="A06-RATE-001",
            evidence=f"{path} — {count}회/{window}초 (임계값={max_req}회, IP={ip})",
            severity=_score_to_severity(score),
            location=f"rate:{path} — Rate Limit 부재",
        )
    return None


# ── 규칙 정의 ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class _Rule:
    rule_id:     str
    description: str
    base_score:  float
    pattern:     re.Pattern[str]
    location_tag: str


# ─── ROLE: 역할·권한 파라미터 직접 주입 ──────────────────────────────────────
# Juice Shop 실제 챌린지: POST /api/Users {"isAdmin":true} → 관리자 계정 생성
_ROLE_RULES: list[_Rule] = [
    _Rule(
        "A06-ROLE-001",
        '"isAdmin":true 직접 주입 — 설계 결함으로 클라이언트가 관리자 권한 획득 (CWE-269)',
        base_score=3.5,
        pattern=re.compile(r'"isAdmin"\s*:\s*true', re.IGNORECASE),
        location_tag="Role Escalation",
    ),
    _Rule(
        "A06-ROLE-002",
        '"role":"admin" 필드 직접 변조 — 역할 기반 접근 제어 우회 (CWE-269)',
        base_score=3.0,
        pattern=re.compile(r'"role"\s*:\s*"(?:admin|administrator|superuser|root|owner)"', re.IGNORECASE),
        location_tag="Role Escalation",
    ),
    _Rule(
        "A06-ROLE-003",
        '"admin":true 또는 "userType":"admin" 변조 — 권한 플래그 직접 조작 (CWE-602)',
        base_score=3.0,
        pattern=re.compile(
            r'"admin"\s*:\s*true'
            r'|"userType"\s*:\s*"admin"'
            r'|"privilege"\s*:\s*"(?:admin|super|root)"',
            re.IGNORECASE,
        ),
        location_tag="Role Escalation",
    ),
]

# ─── PRICE: 가격·금액·할인 변조 ──────────────────────────────────────────────
# Juice Shop: PUT /api/BasketItems/{id} body에 price:0 추가 → 무료 구매
_PRICE_RULES: list[_Rule] = [
    _Rule(
        "A06-PRICE-001",
        '"price":0 또는 음수 — 상품 가격 직접 변조로 무료/역결제 시도 (CWE-841)',
        base_score=2.5,
        pattern=re.compile(r'"price"\s*:\s*(?:0(?:\.0+)?|-\d)', re.IGNORECASE),
        location_tag="Price Manipulation",
    ),
    _Rule(
        "A06-PRICE-002",
        '"amount"/"total"/"cost":0 — 결제 금액 변조로 무료 주문 시도 (CWE-841)',
        base_score=2.5,
        pattern=re.compile(r'"(?:amount|total|cost|payment)"\s*:\s*0(?:\.0+)?', re.IGNORECASE),
        location_tag="Price Manipulation",
    ),
    _Rule(
        "A06-PRICE-003",
        '"discount":100 이상 — 전액 할인 강제 적용 시도 (CWE-841)',
        base_score=2.0,
        pattern=re.compile(r'"discount"\s*:\s*(?:100|[1-9]\d{2,})', re.IGNORECASE),
        location_tag="Price Manipulation",
    ),
    _Rule(
        "A06-PRICE-004",
        '"quantity":0 또는 음수 — 재고 수량 변조 시도 (CWE-841)',
        base_score=1.5,
        pattern=re.compile(r'"quantity"\s*:\s*(?:0|-\d)', re.IGNORECASE),
        location_tag="Price Manipulation",
    ),
]

# ─── MASS: Mass Assignment — 보호 필드 직접 주입 ──────────────────────────────
# Juice Shop: PUT /api/Users/1 {"totpSecret":"JBSWY3DPEHPK3PXP"} → TOTP 우회
_MASS_RULES: list[_Rule] = [
    _Rule(
        "A06-MASS-001",
        '보호 필드(totpSecret/verificationToken/deletedAt) 직접 주입 — Mass Assignment (CWE-915)',
        base_score=2.5,
        pattern=re.compile(
            r'"(?:totpSecret|verificationToken|deletedAt|passwordResetToken|confirmationToken)"\s*:',
            re.IGNORECASE,
        ),
        location_tag="Mass Assignment",
    ),
    _Rule(
        "A06-MASS-002",
        'isActive/isVerified 계정 상태 직접 변조 — 이메일 인증 우회 (CWE-602)',
        base_score=2.0,
        pattern=re.compile(
            r'"(?:isActive|isVerified|emailVerified|active|verified)"\s*:\s*true',
            re.IGNORECASE,
        ),
        location_tag="Mass Assignment",
    ),
]

# ─── ADMIN: 관리자·내부 전용 엔드포인트 직접 접근 ────────────────────────────
# 경로 기반 탐지 (method + path 조합)
@dataclass(frozen=True)
class _AdminRule:
    rule_id:      str
    description:  str
    base_score:   float
    methods:      frozenset[str]
    path_pattern: re.Pattern[str]
    location_tag: str


_ADMIN_RULES: list[_AdminRule] = [
    _AdminRule(
        "A06-ADMIN-001",
        'GET /api/Users — 전체 유저 목록 무단 열람 (Juice Shop 실제 챌린지, CWE-200)',
        base_score=2.5,
        methods=frozenset({"GET"}),
        path_pattern=re.compile(r"^/api/[Uu]sers/?$"),
        location_tag="Admin Endpoint Access",
    ),
    _AdminRule(
        "A06-ADMIN-002",
        'GET /ftp — FTP 파일 브라우저 직접 접근, 민감 파일 노출 (Juice Shop 챌린지, CWE-200)',
        base_score=2.5,
        methods=frozenset({"GET", "HEAD"}),
        path_pattern=re.compile(r"^/ftp(?:/|$)", re.IGNORECASE),
        location_tag="Admin Endpoint Access",
    ),
    _AdminRule(
        "A06-ADMIN-003",
        'GET /api/SecurityQuestions — 보안 질문 목록 노출 (CWE-200)',
        base_score=2.0,
        methods=frozenset({"GET"}),
        path_pattern=re.compile(r"^/api/[Ss]ecurity[Qq]uestions", re.IGNORECASE),
        location_tag="Admin Endpoint Access",
    ),
    _AdminRule(
        "A06-ADMIN-004",
        'API 문서·메트릭 경로 직접 접근 — 내부 구조 노출 (CWE-200)',
        base_score=2.0,
        methods=frozenset({"GET", "HEAD"}),
        path_pattern=re.compile(
            r"^(?:/api-docs|/swagger(?:-ui)?|/metrics|/actuator|/api/swagger|"
            r"/v\d+/api-docs|/openapi\.json|/openapi\.yaml)(?:/|$)",
            re.IGNORECASE,
        ),
        location_tag="Admin Endpoint Access",
    ),
    _AdminRule(
        "A06-ADMIN-005",
        'GET /b2b/v2 — 내부 B2B API 무단 접근 (CWE-200)',
        base_score=2.0,
        methods=frozenset({"GET", "POST", "PUT"}),
        path_pattern=re.compile(r"^/b2b/", re.IGNORECASE),
        location_tag="Admin Endpoint Access",
    ),
]

# ─── STEP: 워크플로우 단계 건너뜀 ────────────────────────────────────────────
_STEP_RULES: list[_AdminRule] = [
    _AdminRule(
        "A06-STEP-001",
        'GET /rest/track-order — 주문 추적 직접 접근, 주문 프로세스 단계 우회 (CWE-841)',
        base_score=1.5,
        methods=frozenset({"GET"}),
        path_pattern=re.compile(r"^/rest/track-order/", re.IGNORECASE),
        location_tag="Workflow Step Skip",
    ),
    _AdminRule(
        "A06-STEP-002",
        'GET /rest/deluxe-membership — 멤버십 검증 없이 직접 활성화 시도 (CWE-841)',
        base_score=2.0,
        methods=frozenset({"GET", "POST", "PUT"}),
        path_pattern=re.compile(r"^/rest/deluxe-membership", re.IGNORECASE),
        location_tag="Workflow Step Skip",
    ),
]


# ── 공통 헬퍼 ────────────────────────────────────────────────────────────────

def _apply_body_rules(body: str, rules: list[_Rule]) -> list[Finding]:
    out: list[Finding] = []
    seen: set[str] = set()
    for rule in rules:
        if rule.rule_id in seen:
            continue
        if not rule.pattern.search(body):
            continue
        seen.add(rule.rule_id)
        score = rule.base_score + _entropy_bonus(body)
        out.append(Finding(
            rule_id=rule.rule_id,
            evidence=body[:150] + ("…" if len(body) > 150 else ""),
            severity=_score_to_severity(score),
            location=f"body — {rule.location_tag}",
        ))
    return out


def _apply_path_rules(
    method: str,
    path: str,
    rules: list[_AdminRule],
) -> list[Finding]:
    out: list[Finding] = []
    for rule in rules:
        if method.upper() not in rule.methods:
            continue
        if not rule.path_pattern.search(path):
            continue
        out.append(Finding(
            rule_id=rule.rule_id,
            evidence=f"{method} {path}",
            severity=_score_to_severity(rule.base_score),
            location=f"path:{path} — {rule.location_tag}",
        ))
    return out


# ── 중복 제거 ─────────────────────────────────────────────────────────────────

_SEV_RANK: dict[Severity, int] = {
    Severity.NONE:     0,
    Severity.LOW:      1,
    Severity.MEDIUM:   2,
    Severity.HIGH:     3,
    Severity.CRITICAL: 4,
}


def _deduplicate(findings: list[Finding]) -> tuple[Finding, ...]:
    best: dict[str, Finding] = {}
    for f in findings:
        prev = best.get(f.rule_id)
        if prev is None or _SEV_RANK[f.severity] > _SEV_RANK[prev.severity]:
            best[f.rule_id] = f
    return tuple(best.values())


# ── 메인 스캔 엔트리 포인트 ──────────────────────────────────────────────────

async def scan(ctx: RequestContext) -> ModuleScanResult:
    """A06:2025 Insecure Design 탐지.

    스캔 범위:
      · 요청 바디 (ROLE, PRICE, MASS)
      · URL 경로 + HTTP 메서드 (ADMIN, STEP)
      · IP + 경로 시계열 (RATE)
    """
    findings: list[Finding] = []
    body    = ctx.body_preview
    method  = ctx.method.upper()
    path    = ctx.path
    headers = {k.lower(): v for k, v in ctx.headers.items()}
    ct      = headers.get("content-type", "")

    # ── 1. ROLE: 역할·권한 파라미터 주입 (body) ──────────────────────────────
    if body and ("json" in ct or body.strip()[:1] in ("{", "[")):
        findings.extend(_apply_body_rules(body, _ROLE_RULES))

    # ── 2. PRICE: 가격·금액 변조 (POST/PUT/PATCH body) ───────────────────────
    if method in ("POST", "PUT", "PATCH") and body:
        findings.extend(_apply_body_rules(body, _PRICE_RULES))

    # ── 3. MASS: 보호 필드 주입 (body) ───────────────────────────────────────
    if body and ("json" in ct or body.strip()[:1] in ("{", "[")):
        findings.extend(_apply_body_rules(body, _MASS_RULES))

    # ── 4. ADMIN: 관리자·내부 엔드포인트 직접 접근 ───────────────────────────
    findings.extend(_apply_path_rules(method, path, _ADMIN_RULES))

    # ── 5. STEP: 워크플로우 단계 건너뜀 ──────────────────────────────────────
    findings.extend(_apply_path_rules(method, path, _STEP_RULES))

    # ── 6. RATE: 단시간 과다 요청 탐지 ───────────────────────────────────────
    rate_finding = _check_rate_limit(ctx)
    if rate_finding:
        findings.append(rate_finding)

    return ModuleScanResult(
        module_id=MODULE_ID,
        owasp_id=OWASP_ID,
        findings=_deduplicate(findings),
    )
