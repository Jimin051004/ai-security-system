"""A10:2025 — Server-Side Request Forgery (SSRF)

프록시 레이어에서 업스트림 전달 전에 탐지·차단한다.
검사 대상: URL 경로, 쿼리스트링, 요청 바디(JSON/Form), SSRF-prone 헤더
탐지 유형: 클라우드 메타데이터 접근, 내부망 접근, 비표준 프로토콜, IP 인코딩 우회, 리다이렉트 남용

[점수 기반 심각도 결정 — 엔트로피(Shannon Entropy) 기법 적용]
  각 탐지 규칙은 base_score(0~100)를 가진다.
  탐지된 문자열의 Shannon Entropy가 높을수록 인코딩/난독화 우회 가능성이 높으므로 가산점 부여.
  SSRF-prone 파라미터명(url, redirect, dest 등)에서 탐지 시 추가 가산.
  총점 → Severity:
    80 이상  → CRITICAL
    55 이상  → HIGH
    30 이상  → MEDIUM
    30 미만  → LOW
"""

from __future__ import annotations

import json
import math
import re
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from typing import Sequence

from owasp.types import Finding, ModuleScanResult, RequestContext, Severity

OWASP_ID = "A10:2025"
MODULE_ID = "a10"
TITLE = "Server-Side Request Forgery (SSRF)"

# ---------------------------------------------------------------------------
# 점수 → Severity 임계값 (엔트로피 가산점 포함한 최종 총점 기준)
# ---------------------------------------------------------------------------

_SCORE_CRITICAL = 80
_SCORE_HIGH     = 55
_SCORE_MEDIUM   = 30

# ---------------------------------------------------------------------------
# SSRF-prone 파라미터 키워드 (여기서 탐지되면 param_bonus +15)
# ---------------------------------------------------------------------------

_SSRF_PARAM_KEYWORDS: frozenset[str] = frozenset({
    "url", "uri", "endpoint", "redirect", "next", "return", "dest",
    "destination", "redir", "ref", "page", "link", "target", "path",
    "src", "source", "proxy", "callback", "fetch", "load", "request",
    "domain", "host", "server", "webhook", "import", "feed", "to",
    "from", "origin", "service", "api", "remote", "external", "site",
    "location", "forward", "open", "image", "resource", "file", "data",
})

# ---------------------------------------------------------------------------
# SSRF-prone 헤더 목록
# ---------------------------------------------------------------------------

_SSRF_HEADERS: frozenset[str] = frozenset({
    "referer",
    "origin",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "x-original-url",
    "x-rewrite-url",
    "x-custom-ip-authorization",
    "true-client-ip",
    "cf-connecting-ip",
})

# ---------------------------------------------------------------------------
# 규칙 정의 구조 — base_score 기반 (a05와 달리 Severity 직접 지정 없음)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    pattern: re.Pattern[str]
    base_score: int   # 0~100 기본 점수 (엔트로피·파라미터 보너스 추가 전)
    description: str


def _r(rule_id: str, pattern: str, base_score: int, description: str) -> _Rule:
    return _Rule(
        rule_id=rule_id,
        pattern=re.compile(pattern, re.IGNORECASE | re.DOTALL),
        base_score=base_score,
        description=description,
    )


# ── 카테고리 1: 클라우드 메타데이터 서버 접근 (가장 위험) ─────────────────────

_CLOUD_META_RULES: tuple[_Rule, ...] = (
    # AWS EC2 인스턴스 메타데이터 서비스 (IMDSv1)
    _r("A10-SSRF-001", r"169\.254\.169\.254", 90,
       "AWS/GCP/Azure 인스턴스 메타데이터 서버(IMDS) 접근 시도"),

    # GCP 메타데이터 서버 내부 도메인
    _r("A10-SSRF-002", r"metadata\.google\.internal", 90,
       "GCP Compute Engine 메타데이터 내부 도메인 접근"),

    # AWS ECS 태스크 메타데이터 (컨테이너 자격증명 포함)
    _r("A10-SSRF-003", r"169\.254\.170\.2", 88,
       "AWS ECS 태스크 메타데이터 엔드포인트 접근 시도"),

    # AWS IAM 자격증명 탈취 (역할 이름+토큰 획득 가능)
    _r("A10-SSRF-004", r"iam[/\\]security[-_]?credentials", 95,
       "AWS IAM 자격증명 탈취 시도 (Access Key 유출 위험)"),

    # AWS EC2 메타데이터 API 경로
    _r("A10-SSRF-005", r"latest[/\\]meta[-_]?data", 90,
       "AWS EC2 메타데이터 API 경로 직접 접근"),

    # GCP 메타데이터 API
    _r("A10-SSRF-006", r"computeMetadata[/\\]v1", 90,
       "GCP Compute Engine 메타데이터 API v1 접근"),

    # Azure IMDS
    _r("A10-SSRF-007", r"169\.254\.169\.254.{0,60}metadata", 88,
       "Azure 인스턴스 메타데이터 서비스(IMDS) 접근 시도"),
)

# ── 카테고리 2: 내부망(Private Network) 직접 접근 ─────────────────────────────

_INTERNAL_NET_RULES: tuple[_Rule, ...] = (
    # 루프백 주소 — 다양한 표기법 포함
    _r("A10-SSRF-008",
       r"(https?|ftp)://(localhost|127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|0\.0\.0\.0)",
       80, "루프백(Loopback) 주소를 통한 내부 서버 직접 접근"),

    # RFC 1918 Class C (192.168.0.0/16)
    _r("A10-SSRF-009",
       r"(https?|ftp)://192\.168\.[0-9]{1,3}\.[0-9]{1,3}",
       65, "RFC 1918 사설망 192.168.x.x 내부 호스트 접근 시도"),

    # RFC 1918 Class A (10.0.0.0/8)
    _r("A10-SSRF-010",
       r"(https?|ftp)://10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
       65, "RFC 1918 사설망 10.x.x.x 내부 호스트 접근 시도"),

    # RFC 1918 Class B (172.16.0.0/12)
    _r("A10-SSRF-011",
       r"(https?|ftp)://172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}",
       65, "RFC 1918 사설망 172.16-31.x.x 내부 호스트 접근 시도"),

    # IPv6 루프백 — ::1, 전체 표기, URL 인코딩
    _r("A10-SSRF-012",
       r"\[::1\]|\[0:0:0:0:0:0:0:1\]|%5B::1%5D|\[0000:0000:0000:0000:0000:0000:0000:0001\]",
       72, "IPv6 루프백 주소(::1) 접근 시도"),

    # 내부 도메인 TLD
    _r("A10-SSRF-013",
       r"(https?|ftp)://[^\s/\"']*\.(internal|local|intranet|corp|private|lan|home|localdomain)\b",
       60, "내부 전용 도메인(internal/local/corp 등) 접근 시도"),

    # Link-Local 주소 (169.254.x.x 전체 — 메타데이터 제외)
    _r("A10-SSRF-014",
       r"(https?|ftp)://169\.254\.[0-9]{1,3}\.[0-9]{1,3}",
       75, "Link-Local 주소(169.254.x.x) 접근 시도"),
)

# ── 카테고리 3: 비표준 프로토콜 남용 ─────────────────────────────────────────

_PROTOCOL_RULES: tuple[_Rule, ...] = (
    # file:// — 로컬 파일 시스템 읽기
    _r("A10-SSRF-015", r"file://", 85,
       "file:// 프로토콜을 통한 로컬 파일 시스템 접근"),

    # gopher:// — 원시 TCP 소켓 통신 (Redis, Memcached 공격에 사용)
    _r("A10-SSRF-016", r"gopher://", 88,
       "gopher:// 프로토콜을 통한 내부 서비스 원시 통신 (Redis/Memcached 공격)"),

    # dict:// — 포트 스캔·배너 수집
    _r("A10-SSRF-017", r"dict://", 75,
       "dict:// 프로토콜을 통한 내부 서비스 포트 스캔"),

    # ldap:// — 내부 LDAP 서버 접근
    _r("A10-SSRF-018", r"(ldap|ldaps)://", 72,
       "LDAP 프로토콜을 통한 내부 디렉터리 서비스 접근"),

    # sftp/tftp/ssh — 파일 전송 프로토콜 남용
    _r("A10-SSRF-019", r"(sftp|tftp|ssh)://", 70,
       "파일 전송 프로토콜(sftp/tftp/ssh)을 통한 내부망 접근"),

    # netdoc:// — Java 구현체 경유 내부 리소스 접근
    _r("A10-SSRF-020", r"netdoc://", 75,
       "netdoc:// 프로토콜을 통한 내부 리소스 접근"),

    # jar:// — Java JAR 파일 처리 중 SSRF
    _r("A10-SSRF-021", r"jar:(https?|ftp|file)://", 78,
       "jar:// 래핑 프로토콜을 통한 SSRF (Java 환경)"),
)

# ── 카테고리 4: IP 주소 인코딩 우회 ─────────────────────────────────────────

_ENCODE_BYPASS_RULES: tuple[_Rule, ...] = (
    # 16진수 IP (0x7f000001 = 127.0.0.1)
    _r("A10-SSRF-022",
       r"(https?|ftp)://0x[0-9a-fA-F]{4,8}(/|\?|$|\s)",
       85, "16진수 인코딩 IP 주소 필터 우회 (0x7f000001 → 127.0.0.1)"),

    # 10진수 IP (2130706433 = 127.0.0.1)
    _r("A10-SSRF-023",
       r"(https?|ftp)://[0-9]{8,10}(/|\?|$|\s)",
       80, "10진수(Decimal) 인코딩 IP 주소 필터 우회 (2130706433 → 127.0.0.1)"),

    # 8진수 IP (0177.0.0.1 = 127.0.0.1)
    _r("A10-SSRF-024",
       r"(https?|ftp)://0[0-9]{2,3}\.[0-9]",
       78, "8진수(Octal) 인코딩 IP 주소 필터 우회 (0177.0.0.1 → 127.0.0.1)"),

    # URL auth 필드 우회 (http://attacker@192.168.1.1)
    _r("A10-SSRF-025",
       r"(https?|ftp)://[^\s@]{1,100}@(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)",
       82, "URL 자격증명 필드를 이용한 내부망 접근 우회 (http://evil@192.168.x.x)"),

    # URL 단편화 우회 (http://127.1 = 127.0.0.1 on some parsers)
    _r("A10-SSRF-026",
       r"(https?|ftp)://127\.[0-9]+(/|\?|$|\s)",
       76, "단축 표기 IP(127.1 → 127.0.0.1) 파서 우회"),
)

# ── 카테고리 5: 리다이렉트 파라미터 남용 ─────────────────────────────────────

_REDIRECT_RULES: tuple[_Rule, ...] = (
    # SSRF-prone 파라미터에 절대 URL 지정
    _r("A10-SSRF-027",
       r"(url|uri|redirect|next|return|dest(?:ination)?|redir|ref|page|link|target|src|source|proxy|callback|fetch|to|from|open|remote|service|resource|file)\s*=\s*(https?|ftp|file|gopher|dict|ldap)://",
       50, "리다이렉트/URL 파라미터에 절대 URL 삽입 (Open Redirect → SSRF 체인)"),

    # 프로토콜 상대 URL (//) — 도메인 제어 우회
    _r("A10-SSRF-028",
       r"(url|uri|redirect|next|return|dest(?:ination)?|redir|ref|page|link|target)\s*=\s*//[^/\s]",
       45, "프로토콜 상대 URL(//) 리다이렉트 — 외부 도메인 제어 가능"),
)

# 모든 규칙 통합
_ALL_RULES: tuple[_Rule, ...] = (
    *_CLOUD_META_RULES,
    *_INTERNAL_NET_RULES,
    *_PROTOCOL_RULES,
    *_ENCODE_BYPASS_RULES,
    *_REDIRECT_RULES,
)

# ---------------------------------------------------------------------------
# 엔트로피 기반 점수 계산
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """문자열의 Shannon Entropy(비트/문자)를 계산한다.

    낮음(0.0~2.0): 단조로운 값 (/etc/passwd, 192.168.1.1 등)
    중간(2.0~4.0): 일반 URL 경로
    높음(4.5~6.0): Base64·URL 이중 인코딩 등 난독화 가능성 높음
    """
    if len(s) < 4:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _entropy_bonus(matched_value: str) -> int:
    """탐지된 값의 Shannon Entropy에 따라 가산점을 반환한다.

    높은 엔트로피 → 인코딩/난독화 우회 시도 가능성 → 점수 상향.
    """
    entropy = _shannon_entropy(matched_value)
    if entropy >= 5.5:   # Base64, 이중 URL 인코딩 등 강한 난독화
        return 20
    elif entropy >= 4.5: # URL 인코딩, 부분 난독화
        return 12
    elif entropy >= 3.5: # 일반적 인코딩 포함
        return 5
    return 0


def _score_to_severity(score: int) -> Severity:
    """총점(0~100+)을 OWASP Severity enum으로 변환한다."""
    if score >= _SCORE_CRITICAL:
        return Severity.CRITICAL
    if score >= _SCORE_HIGH:
        return Severity.HIGH
    if score >= _SCORE_MEDIUM:
        return Severity.MEDIUM
    return Severity.LOW

# ---------------------------------------------------------------------------
# 디코딩 헬퍼 — URL 인코딩 우회 대응
# ---------------------------------------------------------------------------

def _decode_layers(value: str) -> list[str]:
    """원본, 1회 URL 디코딩, 2회 URL 디코딩(이중 인코딩) 변형을 모두 반환한다."""
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

# ---------------------------------------------------------------------------
# 핵심 스캔 로직
# ---------------------------------------------------------------------------

def _param_bonus(label: str) -> int:
    """라벨(파라미터명/헤더명)이 SSRF-prone 키워드를 포함하면 가산점 반환."""
    lower = label.lower()
    for kw in _SSRF_PARAM_KEYWORDS:
        if kw in lower:
            return 15
    return 0


def _scan_value(label: str, value: str) -> list[Finding]:
    """단일 (label, value) 쌍에 모든 SSRF 규칙을 적용한다.

    총점 = base_score + entropy_bonus(탐지된 문자열) + param_bonus(파라미터명)
    총점 → Severity 매핑으로 Finding 생성.
    """
    findings: list[Finding] = []
    variants = _decode_layers(value)
    p_bonus = _param_bonus(label)

    for rule in _ALL_RULES:
        for variant in variants:
            m = rule.pattern.search(variant)
            if m:
                matched = m.group(0)[:200]
                e_bonus = _entropy_bonus(matched)
                total   = min(100, rule.base_score + e_bonus + p_bonus)
                sev     = _score_to_severity(total)
                findings.append(Finding(
                    rule_id=rule.rule_id,
                    evidence=(
                        f"{rule.description} | "
                        f"탐지값: {matched!r} | "
                        f"총점: {total}점 "
                        f"(기본 {rule.base_score} + 엔트로피 {e_bonus} + 파라미터 {p_bonus})"
                    ),
                    severity=sev,
                ))
                break  # 동일 규칙의 variant 중복 Finding 방지

    return findings


def _collect_targets(ctx: RequestContext) -> list[tuple[str, str]]:
    """(label, value) 쌍 목록 — SSRF 스캔 대상 전체 추출."""
    targets: list[tuple[str, str]] = []

    # URL 경로
    targets.append(("path", ctx.path))

    # 쿼리스트링 전체 + 파라미터별
    if ctx.query_string:
        targets.append(("query_raw", ctx.query_string))
        try:
            parsed = urllib.parse.parse_qs(ctx.query_string, keep_blank_values=True)
            for key, values in parsed.items():
                for v in values:
                    targets.append((f"query.{key}", v))
        except Exception:
            pass

    # 요청 바디 미리보기
    if ctx.body_preview:
        targets.append(("body", ctx.body_preview))
        # JSON 바디 — 재귀 평탄화하여 모든 리프 값 스캔
        try:
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

    # SSRF-prone 헤더 값
    for name, val in ctx.headers.items():
        if name.lower() in _SSRF_HEADERS:
            targets.append((f"header.{name}", val))

    return targets


def _flatten_json(obj: object, prefix: str = "") -> list[tuple[str, object]]:
    """중첩 JSON 객체를 재귀적으로 펼쳐 (경로, 값) 쌍을 반환한다."""
    items: list[tuple[str, object]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            items.extend(_flatten_json(v, key))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            items.extend(_flatten_json(v, f"{prefix}[{i}]"))
    else:
        items.append((prefix, obj))
    return items


def _deduplicate(findings: Sequence[Finding]) -> tuple[Finding, ...]:
    """동일 rule_id 는 가장 심각한 Finding 하나만 유지한다."""
    _SEV_RANK = {
        Severity.CRITICAL: 4, Severity.HIGH: 3,
        Severity.MEDIUM: 2,   Severity.LOW: 1, Severity.NONE: 0,
    }
    best: dict[str, Finding] = {}
    for f in findings:
        existing = best.get(f.rule_id)
        if existing is None or _SEV_RANK[f.severity] > _SEV_RANK[existing.severity]:
            best[f.rule_id] = f
    return tuple(best.values())

# ---------------------------------------------------------------------------
# 차단 HTML 페이지 — SSRF 전용 메시지
# ---------------------------------------------------------------------------

_SSRF_CATEGORY_MAP: dict[str, str] = {
    "A10-SSRF-001": "클라우드 메타데이터 서버 접근",
    "A10-SSRF-002": "클라우드 메타데이터 서버 접근",
    "A10-SSRF-003": "클라우드 메타데이터 서버 접근",
    "A10-SSRF-004": "AWS IAM 자격증명 탈취 시도",
    "A10-SSRF-005": "클라우드 메타데이터 API 접근",
    "A10-SSRF-006": "클라우드 메타데이터 API 접근",
    "A10-SSRF-007": "클라우드 메타데이터 서버 접근",
    "A10-SSRF-008": "루프백 주소 내부 접근",
    "A10-SSRF-009": "내부망(사설망) 접근",
    "A10-SSRF-010": "내부망(사설망) 접근",
    "A10-SSRF-011": "내부망(사설망) 접근",
    "A10-SSRF-012": "IPv6 루프백 접근",
    "A10-SSRF-013": "내부 도메인 접근",
    "A10-SSRF-014": "Link-Local 주소 접근",
    "A10-SSRF-015": "파일 시스템 접근 (file://)",
    "A10-SSRF-016": "gopher:// 프로토콜 남용",
    "A10-SSRF-017": "비표준 프로토콜 남용",
    "A10-SSRF-018": "LDAP 프로토콜 남용",
    "A10-SSRF-019": "비표준 프로토콜 남용",
    "A10-SSRF-020": "비표준 프로토콜 남용",
    "A10-SSRF-021": "jar:// 프로토콜 남용",
    "A10-SSRF-022": "16진수 IP 인코딩 우회",
    "A10-SSRF-023": "10진수 IP 인코딩 우회",
    "A10-SSRF-024": "8진수 IP 인코딩 우회",
    "A10-SSRF-025": "URL 자격증명 필드 우회",
    "A10-SSRF-026": "단축 IP 표기 우회",
    "A10-SSRF-027": "리다이렉트 파라미터 SSRF",
    "A10-SSRF-028": "프로토콜 상대 URL 우회",
}

_SEV_RANK_BLOCK: dict[Severity, int] = {
    Severity.CRITICAL: 5, Severity.HIGH: 4,
    Severity.MEDIUM: 3,   Severity.LOW: 2, Severity.NONE: 1,
}

_SEV_CSS_BLOCK: dict[Severity, tuple[str, str]] = {
    Severity.CRITICAL: ("CRITICAL", "sev-critical"),
    Severity.HIGH:     ("HIGH",     "sev-high"),
    Severity.MEDIUM:   ("MEDIUM",   "sev-medium"),
    Severity.LOW:      ("LOW",      "sev-low"),
    Severity.NONE:     ("NONE",     "sev-low"),
}

_BLOCK_PAGE_CSS = """
  *{box-sizing:border-box;margin:0;padding:0}
  body{
    min-height:100vh;display:flex;align-items:center;justify-content:center;
    padding:2rem;
    font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
    color:#f0f4fc;
    background:#060912;
    background:
      radial-gradient(ellipse 110% 85% at 5% -15%,rgba(59,130,246,.28),transparent 52%),
      radial-gradient(ellipse 90% 70% at 95% 5%,rgba(248,113,113,.22),transparent 48%),
      linear-gradient(168deg,#0d1326 0%,#080c18 38%,#060912 100%);
  }
  .card{
    background:linear-gradient(155deg,rgba(30,38,62,.88),rgba(14,18,32,.96));
    border:1px solid rgba(248,113,113,.4);border-radius:16px;
    padding:2rem 2.5rem;max-width:660px;width:100%;
    box-shadow:0 8px 40px rgba(248,113,113,.12),0 4px 24px rgba(0,0,0,.45);
  }
  .icon{font-size:2.75rem;margin-bottom:.55rem}
  h1{font-size:1.45rem;font-weight:800;color:#fca5a5;
     margin-bottom:.3rem;letter-spacing:-.03em;line-height:1.3}
  .subtitle{font-size:.875rem;color:#8b9cc4;margin-bottom:1.25rem;line-height:1.6}
  .category-badge{
    display:inline-flex;align-items:center;gap:.4rem;
    padding:.38rem .9rem;margin-bottom:1.25rem;
    background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.32);
    border-radius:999px;font-size:.82rem;font-weight:700;color:#fca5a5;
  }
  .score-bar{
    display:flex;align-items:center;gap:.75rem;
    margin-bottom:1.1rem;
  }
  .score-label{font-size:.72rem;color:#8b9cc4;white-space:nowrap}
  .score-track{
    flex:1;height:8px;background:rgba(255,255,255,.08);
    border-radius:999px;overflow:hidden;
  }
  .score-fill{height:100%;border-radius:999px;transition:width .4s}
  .score-fill.critical{background:linear-gradient(90deg,#ef4444,#dc2626)}
  .score-fill.high    {background:linear-gradient(90deg,#f97316,#ea580c)}
  .score-fill.medium  {background:linear-gradient(90deg,#eab308,#ca8a04)}
  .score-fill.low     {background:linear-gradient(90deg,#22c55e,#16a34a)}
  .score-num{font-size:.78rem;font-weight:700;color:#f0f4fc;
             min-width:3rem;text-align:right;font-variant-numeric:tabular-nums}
  .findings{
    background:rgba(0,0,0,.22);border:1px solid rgba(129,140,248,.15);
    border-radius:10px;overflow:hidden;margin-bottom:1.5rem;
  }
  .finding-row{
    display:flex;align-items:flex-start;gap:.75rem;
    padding:.6rem .9rem;border-top:1px solid rgba(255,255,255,.04);font-size:.78rem;
  }
  .finding-row:first-child{border-top:none}
  .sev{flex-shrink:0;padding:.18rem .52rem;border-radius:999px;
       font-size:.66rem;font-weight:700;letter-spacing:.04em}
  .sev-critical{background:rgba(239,68,68,.18);color:#fca5a5;border:1px solid rgba(239,68,68,.32)}
  .sev-high    {background:rgba(251,146,60,.15);color:#fdba74;border:1px solid rgba(251,146,60,.28)}
  .sev-medium  {background:rgba(250,204,21,.12);color:#fde047;border:1px solid rgba(250,204,21,.22)}
  .sev-low     {background:rgba(52,211,153,.1);color:#34d399;border:1px solid rgba(52,211,153,.2)}
  .rule-id{color:#a5b4fc;font-family:ui-monospace,"SF Mono",Consolas,monospace;
           font-size:.71rem;margin-bottom:.15rem}
  .evidence{color:#8b9cc4;word-break:break-all;line-height:1.4}
  .footer{font-size:.73rem;color:#8b9cc4;line-height:1.65}
  .back-btn{
    display:inline-flex;align-items:center;gap:.45rem;margin-top:1.1rem;
    padding:.55rem 1.2rem;
    background:linear-gradient(135deg,#3b82f6,#6366f1 50%,#a855f7);
    border:none;border-radius:10px;color:#fff;font-size:.85rem;font-weight:600;
    font-family:inherit;cursor:pointer;text-decoration:none;
    box-shadow:0 4px 20px rgba(99,102,241,.3);transition:filter .15s,transform .15s;
  }
  .back-btn:hover{filter:brightness(1.1);transform:translateY(-1px)}
"""


def _html_esc(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )


def _infer_category(findings: tuple[Finding, ...]) -> str:
    """가장 심각한 Finding의 SSRF 카테고리 이름을 반환한다."""
    sorted_f = sorted(findings, key=lambda f: _SEV_RANK_BLOCK.get(f.severity, 0), reverse=True)
    for f in sorted_f:
        cat = _SSRF_CATEGORY_MAP.get(f.rule_id)
        if cat:
            return cat
    return "서버 측 요청 위조 (SSRF)"


def _max_score_from_findings(findings: tuple[Finding, ...]) -> int:
    """탐지된 Finding에서 최고 점수를 추출한다 (evidence 문자열 파싱)."""
    best = 0
    for f in findings:
        # evidence: "... | 총점: 90점 (..."
        try:
            part = f.evidence.split("총점:")[1].split("점")[0].strip()
            best = max(best, int(part))
        except Exception:
            pass
    return best


def make_block_html(findings: tuple[Finding, ...]) -> str:
    """SSRF 탐지 시 브라우저에 반환할 403 차단 HTML 페이지를 생성한다."""
    category   = _infer_category(findings)
    max_score  = _max_score_from_findings(findings)
    top_sev    = sorted(findings, key=lambda f: _SEV_RANK_BLOCK.get(f.severity, 0), reverse=True)
    sev_label  = top_sev[0].severity.value.upper() if top_sev else "HIGH"
    sev_cls    = top_sev[0].severity.value.lower() if top_sev else "high"
    title      = f"SSRF 공격이 차단되었습니다"

    # 점수 바 너비
    bar_width = min(100, max_score)

    sorted_findings = sorted(findings, key=lambda f: _SEV_RANK_BLOCK.get(f.severity, 0), reverse=True)
    rows: list[str] = []
    for f in sorted_findings:
        lbl, css = _SEV_CSS_BLOCK.get(f.severity, ("?", "sev-low"))
        ev = f.evidence[:140] + "…" if len(f.evidence) > 140 else f.evidence
        rows.append(
            f'<div class="finding-row">'
            f'<span class="sev {css}">{lbl}</span>'
            f'<div>'
            f'<div class="rule-id">{_html_esc(f.rule_id)}</div>'
            f'<div class="evidence">{_html_esc(ev)}</div>'
            f'</div></div>'
        )
    findings_html = "\n".join(rows)

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WAF — SSRF 차단됨</title>
  <style>{_BLOCK_PAGE_CSS}</style>
</head>
<body>
  <div class="card">
    <div class="icon">🚫</div>
    <h1>{_html_esc(title)}</h1>
    <p class="subtitle">
      WAF(Web Application Firewall)가 서버 내부 리소스로의 위조 요청(SSRF)을 탐지하여<br>
      이 요청을 업스트림 서버로 전달하지 않고 차단했습니다.
    </p>
    <div class="category-badge">🎯 {_html_esc(category)}</div>
    <div class="score-bar">
      <span class="score-label">위험 점수</span>
      <div class="score-track">
        <div class="score-fill {sev_cls}" style="width:{bar_width}%"></div>
      </div>
      <span class="score-num">{max_score}점 · {sev_label}</span>
    </div>
    <div class="findings">
{findings_html}
    </div>
    <p class="footer">
      OWASP A10:2025 — Server-Side Request Forgery (SSRF) 정책에 의해 차단되었습니다.<br>
      내부 서버·클라우드 메타데이터·사설망 주소로의 요청은 허용되지 않습니다.<br>
      정상적인 요청이라면 관리자에게 문의하세요.
    </p>
    <a class="back-btn" href="javascript:history.back()">← 이전 페이지로</a>
  </div>
</body>
</html>"""

# ---------------------------------------------------------------------------
# 공개 인터페이스 — detector.py 가 호출하는 진입점
# ---------------------------------------------------------------------------

async def scan(ctx: RequestContext) -> ModuleScanResult:
    """A10:2025 SSRF — 요청의 모든 입력값을 검사하여 SSRF 패턴을 탐지한다.

    탐지 → Finding(rule_id, evidence, severity) 반환.
    severity 는 base_score + entropy_bonus + param_bonus 총점으로 결정.
    """
    all_findings: list[Finding] = []

    for label, value in _collect_targets(ctx):
        findings = _scan_value(label, value)
        all_findings.extend(findings)

    return ModuleScanResult(
        module_id=MODULE_ID,
        owasp_id=OWASP_ID,
        findings=_deduplicate(all_findings),
    )
