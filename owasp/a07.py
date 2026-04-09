"""A07:2025 — Authentication Failures (인증 실패)

인증 메커니즘의 설계·구현 결함으로 공격자가 계정 침해, 인증 우회,
세션 탈취를 시도하는 취약점을 탐지한다.

관련 CWE: CWE-287, CWE-307, CWE-347, CWE-384, CWE-521, CWE-598, CWE-798

────────────────────────────────────────────────────────────────────────────────
Juice Shop 검증 시나리오 (사전 검증 완료 — 탐지 O / 정상 요청 false positive 없음)
────────────────────────────────────────────────────────────────────────────────
Rule              | 탐지 내용                                    | Juice Shop 테스트
──────────────────┼──────────────────────────────────────────────┼────────────────────────────────────────
A07-JWT-001       | JWT alg:none — 서명 검증 완전 우회            | Bearer 헤더에 alg:none JWT 전송
A07-JWT-002       | JWT 서명 누락 — 무서명 토큰 전송              | header.payload. (서명 파트 빈 문자열)
A07-JWT-003       | JWT payload 권한 변조 — role:admin 삽입       | payload.data.role="admin" 변조 후 전송
A07-CRED-001      | 브루트포스 — 동일 IP 로그인 10회/60초 반복    | /rest/user/login 반복 POST
A07-CRED-002      | 크리덴셜 스터핑 — 동일 IP 다중 이메일 시도    | 60초 내 5+ 이메일로 로그인 시도
A07-CRED-003      | 기본·약한 패스워드 — 알려진 취약 비밀번호 사용 | password="admin123" 등 로그인 시도
A07-SESS-001      | 세션 ID URL 노출 — 세션 고정·탈취 위험       | ?token=xxx, ?session=xxx, ?jwt=xxx
A07-ENUM-001      | 계정 열거 — 30초 내 3+ 이메일 주소 스캔       | 빠른 간격으로 다른 이메일 반복 로그인
────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import base64
import json
import re
import time
from collections import defaultdict

from owasp.types import Finding, ModuleScanResult, RequestContext, Severity

# ── 모듈 메타데이터 ──────────────────────────────────────────────────────────

MODULE_ID = "a07"
OWASP_ID  = "A07:2025"
TITLE     = "Authentication Failures"


# ── 점수·심각도 변환 ─────────────────────────────────────────────────────────

def _score_to_severity(score: float) -> Severity:
    if score >= 3.5:
        return Severity.CRITICAL
    if score >= 2.5:
        return Severity.HIGH
    if score >= 1.5:
        return Severity.MEDIUM
    return Severity.LOW


# ── IP 추출 ──────────────────────────────────────────────────────────────────

def _get_client_ip(headers: dict[str, str]) -> str:
    """클라이언트 IP 추출.

    우선순위: X-Forwarded-For → X-Real-IP → 'local'
    request_snapshot.py 가 소켓 IP를 x-real-ip 로 주입하므로
    로컬 프록시 환경에서도 실제 클라이언트 IP가 전달된다.
    """
    xff = headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    rip = headers.get("x-real-ip", "")
    if rip:
        return rip.strip()
    return "local"


# ── 엔드포인트 패턴 ──────────────────────────────────────────────────────────

_LOGIN_RE = re.compile(
    r"^/(?:rest/user/login|api/auth(?:/login)?|login|signin)$",
    re.IGNORECASE,
)
_RESET_RE = re.compile(
    r"^/(?:rest/user/forgot-password|api/auth/reset|password/reset)",
    re.IGNORECASE,
)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. JWT 탐지 — alg:none / 서명 누락 / payload 권한 변조
# ═══════════════════════════════════════════════════════════════════════════════

def _b64url_decode(s: str) -> bytes:
    """Base64url 패딩 자동 보정 후 디코딩."""
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def _check_jwt(headers: dict[str, str]) -> list[Finding]:
    """Authorization: Bearer 헤더에서 JWT 이상 탐지."""
    findings: list[Finding] = []

    auth = headers.get("authorization", "")
    parts = auth.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return findings

    token = parts[1]
    dot_parts = token.split(".")
    if len(dot_parts) < 2:
        return findings

    # JWT 헤더 파싱
    try:
        header_data = json.loads(_b64url_decode(dot_parts[0]))
    except Exception:
        return findings

    alg = str(header_data.get("alg", "")).lower()
    sig = dot_parts[2] if len(dot_parts) > 2 else ""

    # A07-JWT-001: alg:none — 서명 검증 완전 우회 (CWE-287)
    if alg in ("none", ""):
        findings.append(Finding(
            rule_id="A07-JWT-001",
            evidence=f"JWT alg:none 감지 — 서명 없이 유효 토큰으로 인증 우회 시도 (CWE-287, CWE-347)",
            severity=Severity.CRITICAL,
            location="header:Authorization — JWT alg:none",
        ))
        return findings  # 최악 케이스, 이하 검사 불필요

    # A07-JWT-002: 서명 파트 없음 (CWE-347)
    if len(dot_parts) == 2 or sig == "":
        findings.append(Finding(
            rule_id="A07-JWT-002",
            evidence=f"JWT 서명 파트 누락 — 무서명 토큰 전송 (alg={alg!r}, CWE-347)",
            severity=Severity.HIGH,
            location="header:Authorization — JWT missing signature",
        ))

    # A07-JWT-003: payload 권한 변조 (CWE-287)
    try:
        payload_raw = json.loads(_b64url_decode(dot_parts[1]))
        # Juice Shop 구조: {"data": {"id":..., "email":..., "role":...}}
        data = payload_raw.get("data", payload_raw)
        role = str(data.get("role", "")).lower()
        is_admin = data.get("isAdmin", False)
        if role in ("admin", "administrator", "superuser", "root") or is_admin is True:
            findings.append(Finding(
                rule_id="A07-JWT-003",
                evidence=f"JWT payload 권한 변조 — role={role!r}, isAdmin={is_admin} (CWE-287)",
                severity=Severity.CRITICAL,
                location="header:Authorization — JWT payload tampering",
            ))
    except Exception:
        pass

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# 2. 브루트포스 탐지 — 동일 IP, 로그인 엔드포인트 반복 요청 (CWE-307)
# ═══════════════════════════════════════════════════════════════════════════════

# {ip|pattern: [timestamp, ...]}
_brute_store: dict[str, list[float]] = defaultdict(list)

# (경로 패턴, 윈도우(초), 최대 허용 횟수, base_score)
_BRUTE_RULES: list[tuple[re.Pattern[str], int, int, float]] = [
    (_LOGIN_RE, 60,  10, 2.5),   # 로그인: 10회/60초
    (_RESET_RE, 300,  5, 2.5),   # 비밀번호 재설정: 5회/300초
]


def _check_brute_force(ip: str, path: str) -> Finding | None:
    """동일 IP에서 인증 엔드포인트 반복 POST → 브루트포스."""
    now = time.monotonic()

    for pattern, window, max_req, base_score in _BRUTE_RULES:
        if not pattern.match(path):
            continue
        key   = f"{ip}|{pattern.pattern}"
        times = _brute_store[key]
        times[:] = [t for t in times if now - t < window]
        times.append(now)
        count = len(times)
        if count <= max_req:
            continue
        excess = count / max_req
        score  = base_score + min(excess - 1.0, 1.5)
        return Finding(
            rule_id="A07-CRED-001",
            evidence=f"로그인 브루트포스 — {count}회/{window}초, IP={ip}, path={path} (CWE-307)",
            severity=_score_to_severity(score),
            location=f"rate:{path} — Brute Force",
        )
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# 3. 크리덴셜 스터핑 & 계정 열거 — 동일 IP, 다중 이메일 (CWE-307, CWE-204)
# ═══════════════════════════════════════════════════════════════════════════════

# {ip: [(timestamp, email), ...]}
_stuffing_store: dict[str, list[tuple[float, str]]] = defaultdict(list)

_EMAIL_RE = re.compile(
    r'"(?:email|username|user|login)"\s*:\s*"([^"]{3,128})"',
    re.IGNORECASE,
)


def _extract_email(body: str) -> str | None:
    """요청 바디에서 이메일/유저네임 추출."""
    try:
        data = json.loads(body)
        for key in ("email", "username", "user", "login"):
            val = data.get(key, "")
            if val and isinstance(val, str):
                return val.lower().strip()
    except Exception:
        pass
    m = _EMAIL_RE.search(body)
    return m.group(1).lower().strip() if m else None


def _update_stuffing_store(ip: str, email: str) -> None:
    """이메일 시도 기록 (60초 윈도우 유지)."""
    now = time.monotonic()
    entries = _stuffing_store[ip]
    entries[:] = [(t, e) for t, e in entries if now - t < 60]
    entries.append((now, email))


def _check_credential_stuffing(ip: str, path: str, body: str) -> Finding | None:
    """동일 IP, 60초 내 5+ 고유 이메일 → 크리덴셜 스터핑 (CWE-307)."""
    if not _LOGIN_RE.match(path):
        return None
    email = _extract_email(body)
    if not email:
        return None
    _update_stuffing_store(ip, email)
    unique_emails = {e for _, e in _stuffing_store[ip]}
    if len(unique_emails) < 5:
        return None
    score = 2.5 + min((len(unique_emails) - 5) * 0.2, 1.5)
    return Finding(
        rule_id="A07-CRED-002",
        evidence=f"크리덴셜 스터핑 — IP={ip}, 60초 내 {len(unique_emails)}개 이메일 시도 (CWE-307)",
        severity=_score_to_severity(score),
        location="body:email — Credential Stuffing",
    )


def _check_account_enum(ip: str, path: str) -> Finding | None:
    """동일 IP, 30초 내 3+ 고유 이메일 → 계정 열거 (CWE-204)."""
    if not _LOGIN_RE.match(path):
        return None
    now = time.monotonic()
    entries_30s = [(t, e) for t, e in _stuffing_store.get(ip, []) if now - t < 30]
    unique_30s = {e for _, e in entries_30s}
    if len(unique_30s) < 3:
        return None
    # 계정 열거는 능동적 공격 패턴 → HIGH로 차단 대상에 포함
    score = 2.5 + min((len(unique_30s) - 3) * 0.3, 1.5)
    return Finding(
        rule_id="A07-ENUM-001",
        evidence=f"계정 열거 — IP={ip}, 30초 내 {len(unique_30s)}개 이메일 주소 스캔 (CWE-204)",
        severity=_score_to_severity(score),
        location="body:email — Account Enumeration",
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 4. 약한·기본 패스워드 탐지 (CWE-521, CWE-798)
# ═══════════════════════════════════════════════════════════════════════════════

_WEAK_PASSWORDS: frozenset[str] = frozenset({
    # 가장 흔한 약한 패스워드
    "admin", "admin123", "admin@123", "admin1234", "admin!",
    "password", "password1", "password123", "password!", "pass",
    "123456", "1234567", "12345678", "123456789", "1234567890",
    "qwerty", "qwerty123", "letmein", "welcome", "welcome1",
    "monkey", "dragon", "master", "iloveyou", "sunshine", "princess",
    "abc123", "changeme", "default", "secret", "pass123",
    "root", "toor", "test", "test123", "user", "guest",
    "baseball", "football", "superman", "batman", "trustno1",
    # Juice Shop 관련
    "admin123!", "bw9vywo=",
})

_PWD_RE = re.compile(
    r'"(?:password|passwd|pass|pwd)"\s*:\s*"([^"]{1,72})"',
    re.IGNORECASE,
)


def _check_weak_password(path: str, body: str) -> Finding | None:
    """로그인 바디의 알려진 약한/기본 패스워드 탐지."""
    if not _LOGIN_RE.match(path):
        return None
    m = _PWD_RE.search(body)
    if not m:
        return None
    pwd = m.group(1)
    if pwd.lower() in _WEAK_PASSWORDS:
        return Finding(
            rule_id="A07-CRED-003",
            evidence=f"알려진 약한/기본 패스워드 사용 — {pwd!r} (CWE-521, CWE-798)",
            severity=Severity.MEDIUM,
            location="body:password — Weak/Default Password",
        )
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# 5. 세션 ID URL 노출 탐지 (CWE-598, CWE-384)
# ═══════════════════════════════════════════════════════════════════════════════

_SESSION_URL_RE = re.compile(
    r"(?:^|[?&])"
    r"(?:session(?:id)?|sess|token|auth|access_token|jwt|id_token"
    r"|PHPSESSID|JSESSIONID|ASP\.NET_SessionId)"
    r"=([A-Za-z0-9+/=._\-]{16,})",
    re.IGNORECASE,
)


def _check_session_in_url(query_string: str, path: str) -> Finding | None:
    """URL 쿼리스트링에 세션/토큰 노출 → 세션 고정·탈취 위험."""
    if not query_string:
        return None
    m = _SESSION_URL_RE.search(query_string)
    if not m:
        return None
    return Finding(
        rule_id="A07-SESS-001",
        evidence=f"세션/토큰이 URL에 노출 — {path}?{m.group(0)[:60]} (CWE-598, CWE-384)",
        severity=Severity.MEDIUM,
        location="query — Session/Token in URL",
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 중복 제거
# ═══════════════════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════════════════
# 메인 스캔 엔트리 포인트
# ═══════════════════════════════════════════════════════════════════════════════

async def scan(ctx: RequestContext) -> ModuleScanResult:
    """A07:2025 Authentication Failures 탐지.

    스캔 레이어:
      1. JWT: alg:none / 서명 누락 / payload 권한 변조
      2. 브루트포스: 동일 IP 로그인 반복 (rate tracking)
      3. 크리덴셜 스터핑: 동일 IP 다중 이메일 (stuffing store)
      4. 약한·기본 패스워드
      5. 세션 ID URL 노출
      6. 계정 열거: 단시간 다중 이메일 스캔
    """
    findings: list[Finding] = []
    headers  = {k.lower(): v for k, v in ctx.headers.items()}
    body     = ctx.body_preview
    path     = ctx.path
    method   = ctx.method.upper()
    qs       = ctx.query_string
    ip       = _get_client_ip(headers)

    # ── 1. JWT: 알고리즘 조작·서명 누락·payload 변조 ─────────────────────────
    findings.extend(_check_jwt(headers))

    # ── 2. 브루트포스: 동일 IP 로그인 반복 ──────────────────────────────────
    if method == "POST":
        bf = _check_brute_force(ip, path)
        if bf:
            findings.append(bf)

    # ── 3. 크리덴셜 스터핑 (stuffing store 갱신 포함) ────────────────────────
    if method == "POST" and body:
        cs = _check_credential_stuffing(ip, path, body)
        if cs:
            findings.append(cs)

    # ── 4. 약한·기본 패스워드 ───────────────────────────────────────────────
    if method == "POST" and body:
        wp = _check_weak_password(path, body)
        if wp:
            findings.append(wp)

    # ── 5. 세션 ID URL 노출 ──────────────────────────────────────────────────
    sess = _check_session_in_url(qs, path)
    if sess:
        findings.append(sess)

    # ── 6. 계정 열거 (stuffing store는 3에서 이미 갱신됨) ────────────────────
    if method == "POST" and body:
        enum_f = _check_account_enum(ip, path)
        if enum_f:
            findings.append(enum_f)

    return ModuleScanResult(
        module_id=MODULE_ID,
        owasp_id=OWASP_ID,
        findings=_deduplicate(findings),
    )
