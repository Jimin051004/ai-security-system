"""A06:2025 — Insecure Design (안전하지 않은 설계)

비즈니스 로직의 구조적 보안 결함을 탐지한다.
코드 버그가 아닌, 처음부터 보안 제어가 설계에 없는 취약점을 대상으로 한다.

탐지 전략 (A05 Injection 과 동일한 방식으로):
  1. json.loads() 파싱 기반 — 키-값 정밀 탐지 (PRIMARY)
  2. 정규식 스캔          — JSON 파싱 실패 시 폴백   (FALLBACK)
  3. 쿼리스트링 파라미터  — GET 파라미터 변조 탐지
  4. URL 경로 + 메서드    — 관리자 경로 직접 접근 탐지
  5. 디렉터리 리스팅·경로 탐색 — .. / .git / backup·uploads 등
  6. IP 시계열 카운터     — Rate Limit 부재 탐지

관련 CWE: CWE-269, CWE-434, CWE-522, CWE-602, CWE-657, CWE-799, CWE-841, CWE-915

────────────────────────────────────────────────────────────────────────────────
Juice Shop 검증 시나리오
────────────────────────────────────────────────────────────────────────────────
Rule              | 탐지 내용                            | Juice Shop 호출 예시
──────────────────┼──────────────────────────────────────┼──────────────────────────────────────────
A06-ROLE-001      | isAdmin:true 관리자 권한 직접 주입    | POST /api/Users {"isAdmin":true,...}
A06-ROLE-002      | role:"admin" 역할 필드 직접 변조      | PUT  /api/Users/5 {"role":"admin"}
A06-ROLE-003      | admin:true / userType:admin 기타 패턴 | POST body: {"admin":true}
A06-PRICE-001     | price ≤ 0 — 가격 변조                | PUT  /api/BasketItems/1 {"price":0}
A06-PRICE-002     | amount/total/cost ≤ 0 — 결제 변조    | POST /api/Orders {"total":0}
A06-PRICE-003     | discount ≥ 100 — 할인율 변조         | POST /api/Orders {"discount":100}
A06-PRICE-004     | quantity ≤ 0 — 수량 변조             | PUT  /api/BasketItems/1 {"quantity":0}
A06-MASS-001      | 보호 필드 주입 (totpSecret 등)        | PUT  /api/Users/1 {"totpSecret":"..."}
A06-MASS-002      | 계정 상태 필드 변조 (isActive 등)     | POST /api/Users {"isActive":true}
A06-ADMIN-001     | 전체 유저 목록 직접 조회              | GET  /api/Users
A06-ADMIN-002     | FTP 디렉토리 직접 접근                | GET  /ftp
A06-ADMIN-003     | 보안 질문 목록 노출                   | GET  /api/SecurityQuestions
A06-ADMIN-004     | API 문서·메트릭 노출 경로 접근        | GET  /api-docs /swagger /metrics
A06-ADMIN-005     | 내부 B2B API 무단 접근               | GET  /b2b/v2
A06-ADMIN-006     | API 루트(/api) 직접 접근·탐색         | GET  /api
A06-STEP-001      | 주문 추적 직접 접근 (워크플로우 우회)  | GET  /rest/track-order/{id}
A06-STEP-002      | 멤버십 직접 활성화 시도               | GET  /rest/deluxe-membership
A06-RATE-001      | 동일 IP 단시간 과다 요청 (Rate Limit) | /rest/user/login × 10회/60초
A06-DIR-001       | 경로 내 .. / 인코딩 우회 (디렉터리 탈출) | GET /static/../../../etc/passwd
A06-DIR-002       | .git·.env 등 dot 경로 직접 접근          | GET /.git/config
A06-DIR-003       | 리스팅·백업·업로드 폴더 탐색 경로        | GET /backup/ /uploads/ /cgi-bin/
────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import json
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

# 대시보드「상세」·차단 페이지(증거 쿼리)용 한 줄 요약 — A05 의 description | 탐지값 과 동일 역할
_A06_SUMMARY: dict[str, str] = {
    "A06-ROLE-001": "관리자 권한 플래그(isAdmin) 직접 주입",
    "A06-ROLE-002": "역할(role) 필드를 관리자 계열로 변조",
    "A06-ROLE-003": "admin·userType 등 권한 관련 필드 변조",
    "A06-PRICE-001": "가격(price) 0 이하 등 결제 금액 변조",
    "A06-PRICE-002": "amount/total/cost/payment 0 이하 변조",
    "A06-PRICE-003": "할인율(discount) 100% 이상 등 비정상 할인",
    "A06-PRICE-004": "수량(quantity) 0 이하 변조",
    "A06-MASS-001": "보호 필드(totpSecret 등) 대량 할당 시도",
    "A06-MASS-002": "계정 상태(isActive 등) 필드 무단 변경 시도",
    "A06-ADMIN-001": "관리·목록 API(예: 전체 사용자) 무단 직접 접근",
    "A06-ADMIN-002": "FTP 등 내부 파일 공개 경로 직접 접근",
    "A06-ADMIN-003": "보안 질문 등 설정 메타데이터 노출 경로 접근",
    "A06-ADMIN-004": "API 문서·메트릭·스웨거 등 운영 도구 경로 접근",
    "A06-ADMIN-005": "내부 B2B API 경로 무단 접근",
    "A06-ADMIN-006": "REST API 루트(/api) 직접 접근·비정형 경로 탐색",
    "A06-STEP-001": "주문 추적 등 워크플로 단계 우회·직접 접근",
    "A06-STEP-002": "멤버십 등 유료 기능 활성화 경로 직접 호출",
    "A06-RATE-001": "동일 IP 단시간 과다 요청 — Rate Limit 설계 부재 의심",
    "A06-DIR-001": "경로에 상위 디렉터리(..) 또는 인코딩 우회 시퀀스",
    "A06-DIR-002": "버전관리·환경설정 dot 경로(.git/.env 등) 직접 접근",
    "A06-DIR-003": "백업·업로드·임시·CGI 등 디렉터리 리스팅·탐색 패턴",
}


def _a06_evidence(rule_id: str, tail: str, *, max_tail: int = 220) -> str:
    summary = _A06_SUMMARY.get(rule_id, "안전하지 않은 설계 패턴")
    t = tail.strip()
    if len(t) > max_tail:
        t = t[: max_tail - 1] + "…"
    return f"[A06 불안전한 설계] {summary} | {t}"


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
_rate_store: dict[str, list[float]] = defaultdict(list)

# (path 정규식, 윈도우(초), 최대 허용 횟수, base_score)
# /api/Users 는 ADMIN-001 경로 규칙에서 이미 탐지되므로 제외
_RATE_RULES: list[tuple[re.Pattern[str], int, int, float]] = [
    (re.compile(r"^/rest/user/login$",           re.IGNORECASE), 60,  10, 2.5),
    (re.compile(r"^/rest/user/forgot-password$", re.IGNORECASE), 300,  5, 2.5),
    (re.compile(r"^/api/Feedbacks$",             re.IGNORECASE), 60,   5, 1.5),
    (re.compile(r"^/rest/products/reviews",      re.IGNORECASE), 60,  10, 1.5),
]


def _get_client_ip(headers: dict[str, str]) -> str:
    xff = headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return headers.get("x-real-ip", "unknown")


def _check_rate_limit(ctx: RequestContext) -> Finding | None:
    ip   = _get_client_ip({k.lower(): v for k, v in ctx.headers.items()})
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
            evidence=_a06_evidence(
                "A06-RATE-001",
                f"{path} — {count}회/{window}초 (임계={max_req}회, IP={ip})",
            ),
            severity=_score_to_severity(score),
            location=f"rate:{path} — Rate Limit 부재",
        )
    return None


# ── 경로 규칙 정의 ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class _PathRule:
    rule_id:      str
    base_score:   float
    methods:      frozenset[str]
    path_pattern: re.Pattern[str]
    location_tag: str


_ADMIN_RULES: list[_PathRule] = [
    _PathRule(
        "A06-ADMIN-001",
        base_score=2.5,
        methods=frozenset({"GET"}),
        path_pattern=re.compile(r"^/api/[Uu]sers/?$"),
        location_tag="Admin Endpoint Access",
    ),
    _PathRule(
        "A06-ADMIN-002",
        base_score=2.5,
        methods=frozenset({"GET", "HEAD"}),
        path_pattern=re.compile(r"^/ftp(?:/|$)", re.IGNORECASE),
        location_tag="Admin Endpoint Access",
    ),
    _PathRule(
        "A06-ADMIN-003",
        base_score=2.0,
        methods=frozenset({"GET"}),
        path_pattern=re.compile(r"^/api/[Ss]ecurity[Qq]uestions", re.IGNORECASE),
        location_tag="Admin Endpoint Access",
    ),
    _PathRule(
        "A06-ADMIN-004",
        base_score=2.0,
        methods=frozenset({"GET", "HEAD"}),
        path_pattern=re.compile(
            r"^(?:/api-docs|/swagger(?:-ui)?|/metrics|/actuator|/api/swagger|"
            r"/v\d+/api-docs|/openapi\.json|/openapi\.yaml)(?:/|$)",
            re.IGNORECASE,
        ),
        location_tag="Admin Endpoint Access",
    ),
    _PathRule(
        "A06-ADMIN-005",
        base_score=2.0,
        methods=frozenset({"GET", "POST", "PUT"}),
        path_pattern=re.compile(r"^/b2b/", re.IGNORECASE),
        location_tag="Admin Endpoint Access",
    ),
    # Juice Shop 등: GET /api 만 호출 시 업스트림 500 — 루트 탐색·오설계 노출로 간주 (하위 /api/Users 와 별개)
    _PathRule(
        "A06-ADMIN-006",
        base_score=2.5,
        methods=frozenset({"GET", "HEAD"}),
        path_pattern=re.compile(r"^/api/?$", re.IGNORECASE),
        location_tag="Admin Endpoint Access",
    ),
]

_STEP_RULES: list[_PathRule] = [
    _PathRule(
        "A06-STEP-001",
        base_score=1.5,
        methods=frozenset({"GET"}),
        path_pattern=re.compile(r"^/rest/track-order/", re.IGNORECASE),
        location_tag="Workflow Step Skip",
    ),
    _PathRule(
        "A06-STEP-002",
        base_score=2.0,
        methods=frozenset({"GET", "POST", "PUT"}),
        path_pattern=re.compile(r"^/rest/deluxe-membership", re.IGNORECASE),
        location_tag="Workflow Step Skip",
    ),
]

# 디렉터리 리스팅·민감 폴더 탐색 (FTP 루트는 A06-ADMIN-002 가 담당)
_LISTING_RULES: list[_PathRule] = [
    _PathRule(
        "A06-DIR-002",
        base_score=2.5,
        methods=frozenset({"GET", "HEAD"}),
        path_pattern=re.compile(
            r"^/\.(?:git|svn|hg|bzr|env|htaccess|htpasswd|DS_Store|dockerenv)"
            r"(?:/|$)",
            re.IGNORECASE,
        ),
        location_tag="Sensitive Dot-Path Exposure",
    ),
    _PathRule(
        "A06-DIR-003",
        base_score=2.5,
        methods=frozenset({"GET", "HEAD"}),
        path_pattern=re.compile(
            r"^/(?:"
            r"backup|backups|\.?bak|uploads?|uploaded|dump|dumps|"
            r"old|tmp|temp|temporary|scratch|sandbox|staging|"
            r"download|downloads|export|exports|import|imports|imported|"
            r"private|archive|archives|incoming|outgoing|"
            r"password|passwd|passwords|credentials|"
            r"cgi-bin|icons|htmldocs|wwwroot|public_html|html|"
            r"server-status|server-info"
            r")(?:/|$)",
            re.IGNORECASE,
        ),
        location_tag="Directory Listing Probe",
    ),
]

# 경로 탈출: 원본 + URL 디코드(최대 2회)·백슬래시 정규화
_TRAVERSAL_RE = re.compile(
    r"(?:^|/)\.\.(?:/|[\\]|[;%]|$)"
    r"|(?:^|/)%2e%2e(?:/|%2f|%5c|[\\]|[;%]|$)"
    r"|(?:^|/)%252e%252e(?:/|%252f|%255c|[\\]|[;%]|$)",
    re.IGNORECASE,
)


def _path_variants_for_traversal(path: str) -> tuple[str, ...]:
    p = path or "/"
    seen: set[str] = set()
    out: list[str] = []

    def add(s: str) -> None:
        if s not in seen:
            seen.add(s)
            out.append(s)

    add(p)
    add(p.replace("\\", "/"))
    cur = p
    for _ in range(3):
        try:
            nxt = urllib.parse.unquote(cur)
        except Exception:
            break
        if nxt == cur:
            break
        add(nxt)
        add(nxt.replace("\\", "/"))
        cur = nxt
    return tuple(out)


def _check_path_traversal(path: str) -> Finding | None:
    for v in _path_variants_for_traversal(path):
        if _TRAVERSAL_RE.search(v):
            return Finding(
                rule_id="A06-DIR-001",
                evidence=_a06_evidence(
                    "A06-DIR-001",
                    f"경로: {(path or '/')[:220]}",
                ),
                severity=Severity.HIGH,
                location="path — Path Traversal / Directory Escape",
            )
    return None


# ── 정규식 폴백 규칙 ─────────────────────────────────────────────────────────
# JSON 파싱이 실패했을 때(application/x-www-form-urlencoded 등) 사용

@dataclass(frozen=True)
class _RegexRule:
    rule_id:      str
    base_score:   float
    pattern:      re.Pattern[str]
    location_tag: str


_ROLE_REGEX: list[_RegexRule] = [
    _RegexRule("A06-ROLE-001", 3.5,
               re.compile(r'"isAdmin"\s*:\s*true', re.IGNORECASE),
               "Role Escalation"),
    _RegexRule("A06-ROLE-002", 3.0,
               re.compile(r'"role"\s*:\s*"(?:admin|administrator|superuser|root|owner)"',
                          re.IGNORECASE),
               "Role Escalation"),
    _RegexRule("A06-ROLE-003", 3.0,
               re.compile(r'"admin"\s*:\s*true|"userType"\s*:\s*"admin"', re.IGNORECASE),
               "Role Escalation"),
]

_PRICE_REGEX: list[_RegexRule] = [
    _RegexRule("A06-PRICE-001", 2.5,
               re.compile(r'"price"\s*:\s*(?:0(?:\.0+)?|-\d)', re.IGNORECASE),
               "Price Manipulation"),
    _RegexRule("A06-PRICE-002", 2.5,
               re.compile(r'"(?:amount|total|cost|payment)"\s*:\s*0(?:\.0+)?', re.IGNORECASE),
               "Price Manipulation"),
    _RegexRule("A06-PRICE-003", 2.0,
               re.compile(r'"discount"\s*:\s*(?:100|[1-9]\d{2,})', re.IGNORECASE),
               "Price Manipulation"),
    _RegexRule("A06-PRICE-004", 1.5,
               re.compile(r'"quantity"\s*:\s*(?:0|-\d)', re.IGNORECASE),
               "Price Manipulation"),
]

_MASS_REGEX: list[_RegexRule] = [
    _RegexRule("A06-MASS-001", 2.5,
               re.compile(
                   r'"(?:totpSecret|verificationToken|deletedAt|passwordResetToken|'
                   r'confirmationToken)"\s*:',
                   re.IGNORECASE,
               ),
               "Mass Assignment"),
    _RegexRule("A06-MASS-002", 2.0,
               re.compile(
                   r'"(?:isActive|isVerified|emailVerified|active|verified)"\s*:\s*true',
                   re.IGNORECASE,
               ),
               "Mass Assignment"),
]


# ── 1차 탐지: JSON 파싱 기반 (정밀) ──────────────────────────────────────────

def _check_json_body(body: str, method: str) -> list[Finding]:
    """json.loads() 로 파싱 후 키-값을 직접 검사한다 (A05 와 동일한 정밀 탐지 전략)."""
    try:
        obj = json.loads(body)
    except Exception:
        return []

    if not isinstance(obj, dict):
        return []

    out:  list[Finding] = []
    evid = body[:150] + ("…" if len(body) > 150 else "")

    # ── ROLE ──────────────────────────────────────────────────────────────────
    if obj.get("isAdmin") is True:
        out.append(Finding(
            rule_id="A06-ROLE-001",
            evidence=_a06_evidence("A06-ROLE-001", f"본문 발췌: {evid}"),
            severity=Severity.CRITICAL,
            location="body.isAdmin — Role Escalation",
        ))

    role_val = str(obj.get("role", "")).strip().lower()
    if role_val in ("admin", "administrator", "superuser", "root", "owner"):
        out.append(Finding(
            rule_id="A06-ROLE-002",
            evidence=_a06_evidence(
                "A06-ROLE-002",
                f'role="{obj.get("role")}" | 본문 발췌: {evid}',
            ),
            severity=Severity.HIGH,
            location="body.role — Role Escalation",
        ))

    if obj.get("admin") is True or str(obj.get("userType", "")).lower() == "admin":
        out.append(Finding(
            rule_id="A06-ROLE-003",
            evidence=_a06_evidence("A06-ROLE-003", f"본문 발췌: {evid}"),
            severity=Severity.HIGH,
            location="body — Role Escalation",
        ))

    # ── PRICE (POST/PUT/PATCH 에서만 검사) ────────────────────────────────────
    if method in ("POST", "PUT", "PATCH", "DELETE"):

        price_val = obj.get("price")
        if isinstance(price_val, (int, float)) and price_val <= 0:
            out.append(Finding(
                rule_id="A06-PRICE-001",
                evidence=_a06_evidence(
                    "A06-PRICE-001",
                    f"price={price_val} | 본문 발췌: {evid}",
                ),
                severity=Severity.HIGH,
                location="body.price — Price Manipulation",
            ))

        for field in ("amount", "total", "cost", "payment"):
            fval = obj.get(field)
            if isinstance(fval, (int, float)) and fval <= 0:
                out.append(Finding(
                    rule_id="A06-PRICE-002",
                    evidence=_a06_evidence(
                        "A06-PRICE-002",
                        f"{field}={fval} | 본문 발췌: {evid}",
                    ),
                    severity=Severity.HIGH,
                    location=f"body.{field} — Price Manipulation",
                ))
                break

        disc_val = obj.get("discount")
        if isinstance(disc_val, (int, float)) and disc_val >= 100:
            out.append(Finding(
                rule_id="A06-PRICE-003",
                evidence=_a06_evidence(
                    "A06-PRICE-003",
                    f"discount={disc_val} | 본문 발췌: {evid}",
                ),
                severity=Severity.MEDIUM,
                location="body.discount — Price Manipulation",
            ))

        qty_val = obj.get("quantity")
        if isinstance(qty_val, (int, float)) and qty_val <= 0:
            out.append(Finding(
                rule_id="A06-PRICE-004",
                evidence=_a06_evidence(
                    "A06-PRICE-004",
                    f"quantity={qty_val} | 본문 발췌: {evid}",
                ),
                severity=Severity.LOW,
                location="body.quantity — Price Manipulation",
            ))

    # ── MASS Assignment ───────────────────────────────────────────────────────
    _protected = {
        "totpSecret", "verificationToken", "deletedAt",
        "passwordResetToken", "confirmationToken",
    }
    for field in _protected:
        if field in obj:
            out.append(Finding(
                rule_id="A06-MASS-001",
                evidence=_a06_evidence(
                    "A06-MASS-001",
                    f'필드 "{field}" | 본문 발췌: {evid}',
                ),
                severity=Severity.HIGH,
                location=f"body.{field} — Mass Assignment",
            ))
            break

    _state_fields = {"isActive", "isVerified", "emailVerified", "active", "verified"}
    for field in _state_fields:
        if obj.get(field) is True:
            out.append(Finding(
                rule_id="A06-MASS-002",
                evidence=_a06_evidence(
                    "A06-MASS-002",
                    f'"{field}": true | 본문 발췌: {evid}',
                ),
                severity=Severity.MEDIUM,
                location=f"body.{field} — Mass Assignment",
            ))
            break

    return out


# ── 2차 탐지: 정규식 폴백 (JSON 파싱 실패 시) ────────────────────────────────

def _apply_regex_rules(
    body: str,
    rules: list[_RegexRule],
    method: str,
    already_found: set[str],
) -> list[Finding]:
    out: list[Finding] = []
    for rule in rules:
        if rule.rule_id in already_found:
            continue
        if not rule.pattern.search(body):
            continue
        score = rule.base_score + _entropy_bonus(body)
        snippet = body[:150] + ("…" if len(body) > 150 else "")
        out.append(Finding(
            rule_id=rule.rule_id,
            evidence=_a06_evidence(rule.rule_id, f"본문 패턴 일치 | 발췌: {snippet}"),
            severity=_score_to_severity(score),
            location=f"body — {rule.location_tag}",
        ))
    return out


# ── 3차 탐지: 쿼리스트링 파라미터 ────────────────────────────────────────────

def _check_query_params(qs: str) -> list[Finding]:
    out: list[Finding] = []
    try:
        params = urllib.parse.parse_qs(qs, keep_blank_values=True)
    except Exception:
        return out

    def _first(key: str) -> str:
        return params.get(key, [""])[0]

    # isAdmin=true in query
    if _first("isAdmin").lower() == "true":
        out.append(Finding(
            rule_id="A06-ROLE-001",
            evidence=_a06_evidence(
                "A06-ROLE-001",
                f"쿼리 isAdmin=true | ?{qs[:120]}{'…' if len(qs) > 120 else ''}",
            ),
            severity=Severity.CRITICAL,
            location="query.isAdmin — Role Escalation",
        ))

    # role=admin in query
    if _first("role").lower() in ("admin", "administrator", "superuser"):
        out.append(Finding(
            rule_id="A06-ROLE-002",
            evidence=_a06_evidence(
                "A06-ROLE-002",
                f"쿼리 role={_first('role')} | ?{qs[:120]}{'…' if len(qs) > 120 else ''}",
            ),
            severity=Severity.HIGH,
            location="query.role — Role Escalation",
        ))

    # price<=0 in query
    if "price" in params:
        try:
            pv = float(_first("price"))
            if pv <= 0:
                out.append(Finding(
                    rule_id="A06-PRICE-001",
                    evidence=_a06_evidence(
                        "A06-PRICE-001",
                        f"쿼리 price={pv} | ?{qs[:120]}{'…' if len(qs) > 120 else ''}",
                    ),
                    severity=Severity.HIGH,
                    location="query.price — Price Manipulation",
                ))
        except ValueError:
            pass

    # discount>=100 in query
    if "discount" in params:
        try:
            dv = float(_first("discount"))
            if dv >= 100:
                out.append(Finding(
                    rule_id="A06-PRICE-003",
                    evidence=_a06_evidence(
                        "A06-PRICE-003",
                        f"쿼리 discount={dv} | ?{qs[:120]}{'…' if len(qs) > 120 else ''}",
                    ),
                    severity=Severity.MEDIUM,
                    location="query.discount — Price Manipulation",
                ))
        except ValueError:
            pass

    return out


# ── 4차 탐지: 경로 기반 ───────────────────────────────────────────────────────

def _apply_path_rules(method: str, path: str, rules: list[_PathRule]) -> list[Finding]:
    out: list[Finding] = []
    for rule in rules:
        if method.upper() not in rule.methods:
            continue
        if not rule.path_pattern.search(path):
            continue
        out.append(Finding(
            rule_id=rule.rule_id,
            evidence=_a06_evidence(
                rule.rule_id,
                f"요청 {method.upper()} {path}",
            ),
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

    스캔 우선순위 (A05 Injection 과 동일한 계층 구조):
      1차 — json.loads() 파싱 → 키-값 직접 검사 (ROLE / PRICE / MASS)
      2차 — 정규식 폴백       → JSON 파싱 실패 시 raw body 스캔
      3차 — 쿼리스트링        → GET 파라미터 변조 탐지
      4th — URL 경로 규칙     → ADMIN / STEP 직접 접근 탐지
      4b  — .. / .git / backup·uploads 등 디렉터리 리스팅·탐색
      5th — IP 시계열 카운터  → RATE-001 Rate Limit 부재
    """
    findings: list[Finding] = []
    body   = ctx.body_preview or ""
    method = ctx.method.upper()
    path   = ctx.path
    qs     = ctx.query_string or ""

    # ─ 1차: JSON 파싱 기반 탐지 ──────────────────────────────────────────────
    if body:
        json_findings = _check_json_body(body, method)
        findings.extend(json_findings)

    # ─ 2차: 정규식 폴백 (1차에서 못 잡은 rule_id 만 추가 검사) ──────────────
    if body:
        already = {f.rule_id for f in findings}
        findings.extend(_apply_regex_rules(body, _ROLE_REGEX,  method, already))
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            already = {f.rule_id for f in findings}
            findings.extend(_apply_regex_rules(body, _PRICE_REGEX, method, already))
        already = {f.rule_id for f in findings}
        findings.extend(_apply_regex_rules(body, _MASS_REGEX,  method, already))

    # ─ 3차: 쿼리스트링 파라미터 탐지 ────────────────────────────────────────
    if qs:
        findings.extend(_check_query_params(qs))

    # ─ 4차: 경로 기반 탐지 (ADMIN / STEP) ────────────────────────────────────
    findings.extend(_apply_path_rules(method, path, _ADMIN_RULES))
    findings.extend(_apply_path_rules(method, path, _STEP_RULES))

    # ─ 4b: 디렉터리 리스팅·경로 탐색 (.. / .git / 공통 폴더명) ───────────────
    trav = _check_path_traversal(path)
    if trav is not None:
        findings.append(trav)
    findings.extend(_apply_path_rules(method, path, _LISTING_RULES))

    # ─ 5차: Rate Limit 탐지 ──────────────────────────────────────────────────
    rate_finding = _check_rate_limit(ctx)
    if rate_finding:
        findings.append(rate_finding)

    return ModuleScanResult(
        module_id=MODULE_ID,
        owasp_id=OWASP_ID,
        findings=_deduplicate(findings),
    ) 