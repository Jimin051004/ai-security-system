"""A10:2025 — Server-Side Request Forgery (SSRF)

프록시 레이어에서 업스트림 전달 전에 탐지·차단한다.

검사 대상:
  URL 경로, 쿼리스트링(파싱+raw), 요청 바디(JSON/Form/XML/raw),
  Cookie 헤더, SSRF-prone 헤더(Referer/Origin/X-Forwarded-Host 등)

탐지 유형 (7개 카테고리, 38개 규칙):
  Cat.1 클라우드 메타데이터 서버  (A10-SSRF-001 ~ 010)
  Cat.2 내부망(RFC 1918) 직접 접근  (A10-SSRF-011 ~ 017)
  Cat.3 비표준 프로토콜 남용          (A10-SSRF-018 ~ 027)
  Cat.4 IP 주소 인코딩 우회            (A10-SSRF-028 ~ 033)
  Cat.5 XML/XXE → SSRF               (A10-SSRF-034 ~ 035)
  Cat.6 리다이렉트 파라미터 남용       (A10-SSRF-036 ~ 037)
  Cat.7 기타 위험 패턴                 (A10-SSRF-038)

[점수 기반 심각도 결정 — Shannon Entropy 기법 적용]
  총점 = base_score + entropy_bonus + param_bonus
  CRITICAL ≥ 80  /  HIGH ≥ 55  /  MEDIUM ≥ 30  /  LOW < 30

[FTP 탐지 정책]
  A10-SSRF-018: ftp:// 독립 규칙 (base 60) → param bonus 포함 시 HIGH/CRITICAL
  A10-SSRF-011: (https?|ftp)://로컬/내부 → CRITICAL (이미 존재)
  → ftp://서버 접속 시 반드시 탐지·차단된다.
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
# 점수 임계값
# ---------------------------------------------------------------------------

_SCORE_CRITICAL = 80
_SCORE_HIGH     = 55
_SCORE_MEDIUM   = 30

# ---------------------------------------------------------------------------
# SSRF-prone 파라미터 키워드 — 포함 시 param_bonus +15
# ---------------------------------------------------------------------------

_SSRF_PARAM_KEYWORDS: frozenset[str] = frozenset({
    "url", "uri", "endpoint", "redirect", "next", "return", "dest",
    "destination", "redir", "ref", "page", "link", "target", "path",
    "src", "source", "proxy", "callback", "fetch", "load", "request",
    "domain", "host", "server", "webhook", "import", "feed", "to",
    "from", "origin", "service", "api", "remote", "external", "site",
    "location", "forward", "open", "image", "resource", "file", "data",
    "ftp", "sftp", "connect", "download", "upload", "read", "write",
    "base", "href", "action", "template", "view", "preview", "render",
})

# ---------------------------------------------------------------------------
# SSRF-prone 헤더 — 값을 스캔할 대상
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
    "x-host",
    "x-http-host-override",
    "x-forwarded-server",
    "forwarded",
    "true-client-ip",
    "cf-connecting-ip",
    "content-location",
    "link",
})

# ---------------------------------------------------------------------------
# 규칙 구조
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    pattern: re.Pattern[str]
    base_score: int
    description: str


def _r(rule_id: str, pattern: str, base_score: int, description: str) -> _Rule:
    return _Rule(
        rule_id=rule_id,
        pattern=re.compile(pattern, re.IGNORECASE | re.DOTALL),
        base_score=base_score,
        description=description,
    )


# ===========================================================================
# 카테고리 1: 클라우드 메타데이터 서버 (A10-SSRF-001 ~ 010)
# ===========================================================================

_CLOUD_META_RULES: tuple[_Rule, ...] = (
    # AWS EC2 IMDSv1 / Azure IMDS — 가장 빈번한 SSRF 표적
    _r("A10-SSRF-001", r"169\.254\.169\.254", 90,
       "AWS/Azure 인스턴스 메타데이터 서버(IMDS) 접근 시도"),

    # GCP 메타데이터 내부 도메인
    _r("A10-SSRF-002", r"metadata\.google\.internal", 90,
       "GCP Compute Engine 메타데이터 내부 도메인 접근"),

    # AWS ECS 태스크 메타데이터 (컨테이너 자격증명)
    _r("A10-SSRF-003", r"169\.254\.170\.2", 88,
       "AWS ECS 태스크 메타데이터 엔드포인트 접근 시도"),

    # AWS IAM 자격증명 경로 — AccessKey/SecretKey 탈취 가능
    _r("A10-SSRF-004", r"iam[/\\]security[-_]?credentials", 95,
       "AWS IAM 자격증명 탈취 시도 (Access Key 유출 위험)"),

    # AWS EC2 메타데이터 API 경로 키워드
    _r("A10-SSRF-005", r"latest[/\\]meta[-_]?data", 90,
       "AWS EC2 메타데이터 API 경로 직접 접근"),

    # GCP 메타데이터 API v1
    _r("A10-SSRF-006", r"computeMetadata[/\\]v1", 90,
       "GCP Compute Engine 메타데이터 API v1 접근"),

    # Azure IMDS — api-version 파라미터 포함 시 식별
    _r("A10-SSRF-007", r"169\.254\.169\.254.{0,80}(metadata|api-version)", 88,
       "Azure IMDS — Metadata: true 헤더 없이도 경로 패턴 탐지"),

    # Alibaba Cloud 메타데이터 (100.100.100.200)
    _r("A10-SSRF-008", r"100\.100\.100\.200", 90,
       "Alibaba Cloud ECS 메타데이터 서버 접근 시도"),

    # Oracle Cloud IMDS
    _r("A10-SSRF-009", r"192\.0\.0\.192|169\.254\.0\.2", 88,
       "Oracle Cloud 인스턴스 메타데이터 서버 접근 시도"),

    # Digital Ocean metadata
    _r("A10-SSRF-010", r"169\.254\.169\.254.{0,40}(digitalocean|droplet)", 85,
       "DigitalOcean Droplet 메타데이터 접근 시도"),
)

# ===========================================================================
# 카테고리 2: 내부망(RFC 1918) 직접 접근 (A10-SSRF-011 ~ 017)
# ===========================================================================

_INTERNAL_NET_RULES: tuple[_Rule, ...] = (
    # 루프백 — http/https/ftp 모두
    _r("A10-SSRF-011",
       r"(https?|ftp)://(localhost|127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|0\.0\.0\.0|0/)",
       80, "루프백(Loopback) 주소를 통한 내부 서버 직접 접근"),

    # 192.168.x.x
    _r("A10-SSRF-012",
       r"(https?|ftp)://192\.168\.[0-9]{1,3}\.[0-9]{1,3}",
       65, "RFC 1918 사설망 192.168.x.x 내부 호스트 접근 시도"),

    # 10.x.x.x
    _r("A10-SSRF-013",
       r"(https?|ftp)://10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
       65, "RFC 1918 사설망 10.x.x.x 내부 호스트 접근 시도"),

    # 172.16-31.x.x
    _r("A10-SSRF-014",
       r"(https?|ftp)://172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}",
       65, "RFC 1918 사설망 172.16-31.x.x 내부 호스트 접근 시도"),

    # IPv6 루프백 (::1 다양한 표기)
    _r("A10-SSRF-015",
       r"\[::1\]|\[0:0:0:0:0:0:0:1\]|%5B::1%5D",
       72, "IPv6 루프백 주소(::1) 접근 시도"),

    # 내부 전용 도메인 TLD
    _r("A10-SSRF-016",
       r"(https?|ftp)://[^\s/\"']*\.(internal|local|intranet|corp|private|lan|home|localdomain)\b",
       60, "내부 전용 도메인(internal/local/corp 등) 접근 시도"),

    # Link-Local 전체 대역 (169.254.x.x — 메타데이터 포함)
    _r("A10-SSRF-017",
       r"(https?|ftp)://169\.254\.[0-9]{1,3}\.[0-9]{1,3}",
       75, "Link-Local 주소(169.254.x.x) 접근 시도"),
)

# ===========================================================================
# 카테고리 3: 비표준 프로토콜 남용 (A10-SSRF-018 ~ 027)
# ===========================================================================

_PROTOCOL_RULES: tuple[_Rule, ...] = (
    # ── [핵심 추가] ftp:// 독립 탐지 ──────────────────────────────────────
    # 웹 앱 요청에서 ftp:// 는 거의 항상 SSRF 시도이다.
    # base 60: param_bonus(+15) 포함 → HIGH(75)/CRITICAL(80) 로 승격
    # ftp://내부IP 는 A10-SSRF-011~014 에서 더 높은 점수로 이미 탐지된다.
    _r("A10-SSRF-018", r"ftp://[^\s\"'<>]{3,}", 60,
       "FTP 프로토콜을 통한 서버 측 리소스 접근 시도 (SSRF via ftp://)"),

    # file:// — 로컬 파일 시스템 읽기
    _r("A10-SSRF-019", r"file://", 85,
       "file:// 프로토콜을 통한 로컬 파일 시스템 접근"),

    # gopher:// — Redis/Memcached 등 내부 서비스 원시 통신
    _r("A10-SSRF-020", r"gopher://", 88,
       "gopher:// 프로토콜을 통한 내부 서비스 원시 TCP 통신 (Redis/Memcached 공격)"),

    # dict:// — 포트 스캔·배너 수집
    _r("A10-SSRF-021", r"dict://", 75,
       "dict:// 프로토콜을 통한 내부 서비스 포트 스캔"),

    # ldap:// — 내부 디렉터리 서비스 접근
    _r("A10-SSRF-022", r"(ldap|ldaps)://", 72,
       "LDAP 프로토콜을 통한 내부 디렉터리 서비스 접근"),

    # sftp/tftp/ssh — 파일 전송 프로토콜 남용
    _r("A10-SSRF-023", r"(sftp|tftp|ssh)://", 70,
       "파일 전송 프로토콜(sftp/tftp/ssh)을 통한 내부망 접근"),

    # telnet:// — 내부 서비스 직접 연결 시도
    _r("A10-SSRF-024", r"telnet://", 75,
       "telnet:// 프로토콜을 통한 내부 서비스 직접 연결 시도"),

    # netdoc:// — Java 구현체 내부 리소스 접근
    _r("A10-SSRF-025", r"netdoc://", 75,
       "netdoc:// 프로토콜을 통한 내부 리소스 접근"),

    # jar:// — Java JAR 처리 중 SSRF
    _r("A10-SSRF-026", r"jar:(https?|ftp|file)://", 78,
       "jar:// 래핑 프로토콜을 통한 SSRF (Java 환경)"),

    # data: URI — 클라이언트/서버 양쪽에서 악용 가능
    _r("A10-SSRF-027", r"data:(text|application|image)/[a-z0-9+\-]+;", 65,
       "data: URI 스킴 삽입 — 서버 측 렌더러/파서 악용 가능"),
)

# ===========================================================================
# 카테고리 4: IP 주소 인코딩 우회 (A10-SSRF-028 ~ 033)
# ===========================================================================

_ENCODE_BYPASS_RULES: tuple[_Rule, ...] = (
    # 16진수 IP (0x7f000001 = 127.0.0.1)
    _r("A10-SSRF-028",
       r"(https?|ftp)://0x[0-9a-fA-F]{4,8}(/|\?|$|\s|:)",
       85, "16진수 인코딩 IP 주소 필터 우회 (0x7f000001 → 127.0.0.1)"),

    # 10진수 IP (2130706433 = 127.0.0.1)
    _r("A10-SSRF-029",
       r"(https?|ftp)://[0-9]{8,10}(/|\?|$|\s|:)",
       80, "10진수(Decimal) 인코딩 IP 주소 필터 우회 (2130706433 → 127.0.0.1)"),

    # 8진수 IP (0177.0.0.1 = 127.0.0.1)
    _r("A10-SSRF-030",
       r"(https?|ftp)://0[0-9]{2,3}\.[0-9]",
       78, "8진수(Octal) 인코딩 IP 주소 필터 우회 (0177.0.0.1 → 127.0.0.1)"),

    # URL auth 필드 우회 (http://evil@192.168.1.1)
    _r("A10-SSRF-031",
       r"(https?|ftp)://[^\s@]{1,100}@(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.)",
       82, "URL 자격증명 필드를 이용한 내부망 접근 우회 (http://evil@192.168.x.x)"),

    # 단축 IP 표기 (http://127.1 = 127.0.0.1)
    _r("A10-SSRF-032",
       r"(https?|ftp)://127\.[0-9]+(/|\?|$|\s|:)",
       76, "단축 표기 IP(127.1 → 127.0.0.1) 파서 우회"),

    # IPv4-mapped IPv6 루프백 (::ffff:127.0.0.1)
    _r("A10-SSRF-033",
       r"\[::ffff:(127\.|192\.168\.|10\.|0\.0\.0\.0)",
       82, "IPv4-mapped IPv6 표기를 이용한 루프백/내부망 우회 (::ffff:127.0.0.1)"),
)

# ===========================================================================
# 카테고리 5: XML/XXE → SSRF (A10-SSRF-034 ~ 035)
# ===========================================================================

_XXE_SSRF_RULES: tuple[_Rule, ...] = (
    # XXE 엔티티 선언에 외부 URL 포함 — XML 파서가 서버 측에서 URL 접근
    _r("A10-SSRF-034",
       r"<!ENTITY\s+\w+\s+(SYSTEM|PUBLIC)\s+[\"'](https?|ftp|file|gopher|dict)://",
       90, "XML XXE 외부 엔티티 선언 — 서버 측 URL 접근 유발 (SSRF via XXE)"),

    # DOCTYPE SYSTEM 선언 (간이 탐지)
    _r("A10-SSRF-035",
       r"<!DOCTYPE\s+\w+\s+(SYSTEM|PUBLIC)\s+[\"'](https?|ftp|file)://",
       85, "XML DOCTYPE SYSTEM/PUBLIC 외부 리소스 선언 (XXE SSRF)"),
)

# ===========================================================================
# 카테고리 6: 리다이렉트 파라미터 남용 (A10-SSRF-036 ~ 037)
# ===========================================================================

_REDIRECT_RULES: tuple[_Rule, ...] = (
    # SSRF-prone 파라미터에 절대 URL 지정
    _r("A10-SSRF-036",
       r"(url|uri|redirect|next|return|dest(?:ination)?|redir|ref|page|link|target|"
       r"src|source|proxy|callback|fetch|to|from|open|remote|service|resource|file|"
       r"ftp|connect|download|base|href|action|template|view|preview)\s*=\s*"
       r"(https?|ftp|file|gopher|dict|ldap|telnet|data)://",
       50, "리다이렉트/URL 파라미터에 절대 URL 삽입 (Open Redirect → SSRF 체인)"),

    # 프로토콜 상대 URL (//) — 도메인 제어 우회
    _r("A10-SSRF-037",
       r"(url|uri|redirect|next|return|dest(?:ination)?|redir|ref|page|link|target)\s*=\s*//[^/\s]",
       45, "프로토콜 상대 URL(//) 리다이렉트 — 외부 도메인 제어 가능"),
)

# ===========================================================================
# 카테고리 7: 기타 위험 패턴 (A10-SSRF-038)
# ===========================================================================

_MISC_RULES: tuple[_Rule, ...] = (
    # CRLF 인젝션을 통한 HTTP 응답 스플리팅 / SSRF 우회
    _r("A10-SSRF-038",
       r"(https?|ftp)://[^\s\"'<>]*(%0d%0a|%0a|%0d|\r\n|\n)[\s\S]*?(get|post|host)[\s\S]*?:",
       85, "CRLF 인젝션이 포함된 URL — HTTP 응답 스플리팅 또는 SSRF 우회 시도"),
)

# 규칙 전체 통합 (카테고리별 순서 유지)
_ALL_RULES: tuple[_Rule, ...] = (
    *_CLOUD_META_RULES,
    *_INTERNAL_NET_RULES,
    *_PROTOCOL_RULES,
    *_ENCODE_BYPASS_RULES,
    *_XXE_SSRF_RULES,
    *_REDIRECT_RULES,
    *_MISC_RULES,
)

# ===========================================================================
# 엔트로피 기반 점수 계산
# ===========================================================================

def _shannon_entropy(s: str) -> float:
    """Shannon Entropy(비트/문자) 계산.

    0.0~2.0 : 단조로운 값 (127.0.0.1, /etc/passwd 등)
    2.0~4.0 : 일반 URL 경로
    4.5~6.0 : Base64 · 이중 URL 인코딩 등 높은 난독화
    """
    if len(s) < 4:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _entropy_bonus(matched_value: str) -> int:
    """탐지 값의 Shannon Entropy → 가산점 반환 (난독화 우회 탐지 강화)."""
    entropy = _shannon_entropy(matched_value)
    if entropy >= 5.5:    # 강한 난독화 (Base64, 이중 URL 인코딩)
        return 20
    elif entropy >= 4.5:  # URL 인코딩, 부분 난독화
        return 12
    elif entropy >= 3.5:  # 일반 인코딩 혼합
        return 5
    return 0


def _score_to_severity(score: int) -> Severity:
    """총점(0~100) → Severity 변환."""
    if score >= _SCORE_CRITICAL:
        return Severity.CRITICAL
    if score >= _SCORE_HIGH:
        return Severity.HIGH
    if score >= _SCORE_MEDIUM:
        return Severity.MEDIUM
    return Severity.LOW

# ===========================================================================
# 디코딩 헬퍼 — URL 인코딩 우회 대응
# ===========================================================================

def _decode_layers(value: str) -> list[str]:
    """원본 + 1~2회 URL 디코딩 변형 반환 (이중 인코딩 우회 탐지)."""
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

# ===========================================================================
# 스캔 핵심 로직
# ===========================================================================

def _param_bonus(label: str) -> int:
    """라벨이 SSRF-prone 키워드를 포함하면 +15 반환."""
    lower = label.lower()
    for kw in _SSRF_PARAM_KEYWORDS:
        if kw in lower:
            return 15
    return 0


_RULE_CATEGORY: dict[str, str] = {
    "A10-SSRF-001": "클라우드 메타데이터(AWS/Azure)",
    "A10-SSRF-002": "클라우드 메타데이터(GCP)",
    "A10-SSRF-003": "클라우드 메타데이터(ECS)",
    "A10-SSRF-004": "IAM 자격증명 탈취",
    "A10-SSRF-005": "AWS 메타데이터 API",
    "A10-SSRF-006": "GCP 메타데이터 API",
    "A10-SSRF-007": "Azure IMDS",
    "A10-SSRF-008": "Alibaba Cloud 메타데이터",
    "A10-SSRF-009": "Oracle Cloud 메타데이터",
    "A10-SSRF-010": "DigitalOcean 메타데이터",
    "A10-SSRF-011": "루프백 주소 접근",
    "A10-SSRF-012": "내부망(192.168.x.x)",
    "A10-SSRF-013": "내부망(10.x.x.x)",
    "A10-SSRF-014": "내부망(172.16-31.x.x)",
    "A10-SSRF-015": "IPv6 루프백(::1)",
    "A10-SSRF-016": "내부 도메인 접근",
    "A10-SSRF-017": "Link-Local 주소",
    "A10-SSRF-018": "FTP 프로토콜 접근",          # ← 신규: ftp:// 독립 탐지
    "A10-SSRF-019": "파일 시스템 접근(file://)",
    "A10-SSRF-020": "gopher:// 프로토콜",
    "A10-SSRF-021": "dict:// 프로토콜",
    "A10-SSRF-022": "LDAP 프로토콜",
    "A10-SSRF-023": "sftp/tftp/ssh 프로토콜",
    "A10-SSRF-024": "telnet:// 프로토콜",          # ← 신규
    "A10-SSRF-025": "netdoc:// 프로토콜",
    "A10-SSRF-026": "jar:// 프로토콜",
    "A10-SSRF-027": "data: URI 스킴",              # ← 신규
    "A10-SSRF-028": "16진수 IP 우회",
    "A10-SSRF-029": "10진수 IP 우회",
    "A10-SSRF-030": "8진수 IP 우회",
    "A10-SSRF-031": "URL 자격증명 우회",
    "A10-SSRF-032": "단축 IP 표기 우회",
    "A10-SSRF-033": "IPv4-mapped IPv6 우회",        # ← 신규
    "A10-SSRF-034": "XML XXE → SSRF",              # ← 신규
    "A10-SSRF-035": "XML DOCTYPE SSRF",             # ← 신규
    "A10-SSRF-036": "리다이렉트 파라미터 SSRF",
    "A10-SSRF-037": "프로토콜 상대 URL",
    "A10-SSRF-038": "CRLF 인젝션 우회",             # ← 신규
}


def _ssrf_category_short(rule_id: str) -> str:
    return _RULE_CATEGORY.get(rule_id, "SSRF 위조 요청")


def _scan_value(
    label: str,
    value: str,
    rules: tuple[_Rule, ...] = _ALL_RULES,
) -> list[Finding]:
    """단일 (label, value) 쌍에 지정 규칙을 적용하고 최고점 Finding 1개를 반환한다.

    최고점 1개 반환 전략:
      → 같은 입력값에서 여러 규칙이 매칭돼도 가장 위험한 1건만 보고.
      → main.py WAF alert 단건 경로 → "규칙: A10-SSRF-018 · 위치: SSRF — query.ftp"
    """
    candidates: list[tuple[int, Finding]] = []
    variants   = _decode_layers(value)
    p_bonus    = _param_bonus(label)

    for rule in rules:
        for variant in variants:
            m = rule.pattern.search(variant)
            if m:
                matched = m.group(0)[:200]
                e_bonus = _entropy_bonus(matched)
                total   = min(100, rule.base_score + e_bonus + p_bonus)
                sev     = _score_to_severity(total)
                cat     = _ssrf_category_short(rule.rule_id)
                candidates.append((total, Finding(
                    rule_id=rule.rule_id,
                    evidence=(
                        f"[A10:SSRF — {cat}] "
                        f"{rule.description} | "
                        f"탐지값: {matched!r} | "
                        f"총점: {total}점 "
                        f"(기본 {rule.base_score} + 엔트로피 {e_bonus} + 파라미터 {p_bonus})"
                    ),
                    severity=sev,
                    location=f"SSRF — {label}",
                )))
                break  # 동일 규칙 variant 중복 방지

    if not candidates:
        return []

    best_score = max(score for score, _ in candidates)
    best = [f for score, f in candidates if score == best_score]
    return [best[0]]  # 동점이면 규칙 순서(위험도 높은 순) 중 첫 번째

# ===========================================================================
# 스캔 대상 수집
# ===========================================================================

# (label, value, rules) 튜플
_ScanTarget = tuple[str, str, tuple[_Rule, ...]]


def _collect_targets(ctx: RequestContext) -> list[_ScanTarget]:
    """요청 전체에서 (label, value, rules) 스캔 대상을 추출한다.

    query_raw / body: 리다이렉트·XXE 규칙만 적용해 중복 Finding 방지.
    파싱된 개별 파라미터: ALL_RULES 적용.
    Cookie: SSRF-prone 쿠키명에서 URL 패턴 스캔.
    """
    targets: list[_ScanTarget] = []

    # ── 1. URL 경로 ──────────────────────────────────────────────────────────
    targets.append(("path", ctx.path, _ALL_RULES))

    # ── 2. 쿼리스트링 ────────────────────────────────────────────────────────
    if ctx.query_string:
        parsed_ok = False
        try:
            parsed = urllib.parse.parse_qs(ctx.query_string, keep_blank_values=True)
            for key, values in parsed.items():
                for v in values:
                    targets.append((f"query.{key}", v, _ALL_RULES))
            parsed_ok = bool(parsed)
        except Exception:
            pass

        raw_rules: tuple[_Rule, ...] = (
            _ALL_RULES if not parsed_ok
            else (*_REDIRECT_RULES, *_XXE_SSRF_RULES)
        )
        targets.append(("query_raw", ctx.query_string, raw_rules))

    # ── 3. 요청 바디 ─────────────────────────────────────────────────────────
    if ctx.body_preview:
        body = ctx.body_preview
        ct   = ctx.headers.get("content-type", "").lower()

        # 3-a. JSON 바디: 재귀 평탄화 후 리프 값 각각 스캔
        json_ok = False
        if "json" in ct or body.lstrip().startswith(("{", "[")):
            try:
                obj = json.loads(body)
                for k, v in _flatten_json(obj):
                    targets.append((f"body.{k}", str(v), _ALL_RULES))
                json_ok = True
            except Exception:
                pass

        # 3-b. URL-encoded 폼 바디
        form_ok = False
        if "application/x-www-form-urlencoded" in ct:
            try:
                parsed_body = urllib.parse.parse_qs(body, keep_blank_values=True)
                for key, values in parsed_body.items():
                    for v in values:
                        targets.append((f"form.{key}", v, _ALL_RULES))
                form_ok = bool(parsed_body)
            except Exception:
                pass

        # 3-c. XML/XXE 바디: 엔티티 선언 포함 여부 탐지
        if "xml" in ct or body.lstrip().startswith("<"):
            targets.append(("body_xml", body, (*_XXE_SSRF_RULES, *_PROTOCOL_RULES)))

        # 3-d. raw 바디: JSON/폼 파싱 실패 시 전체 대상, 성공 시 리다이렉트·XXE만
        if not json_ok and not form_ok:
            targets.append(("body", body, _ALL_RULES))
        else:
            targets.append(("body", body, (*_REDIRECT_RULES, *_XXE_SSRF_RULES)))

    # ── 4. SSRF-prone 헤더 ───────────────────────────────────────────────────
    for name, val in ctx.headers.items():
        if name.lower() in _SSRF_HEADERS:
            targets.append((f"header.{name}", val, _ALL_RULES))

    # ── 5. Cookie 헤더 (쿠키명이 SSRF 키워드와 일치하는 값 스캔) ────────────────
    cookie_raw = ctx.headers.get("cookie", "")
    if cookie_raw:
        try:
            for part in cookie_raw.split(";"):
                part = part.strip()
                if "=" in part:
                    cname, _, cval = part.partition("=")
                    cname = cname.strip().lower()
                    cval  = cval.strip()
                    for kw in _SSRF_PARAM_KEYWORDS:
                        if kw in cname and cval:
                            targets.append((f"cookie.{cname}", cval, _ALL_RULES))
                            break
        except Exception:
            pass

    return targets


def _flatten_json(obj: object, prefix: str = "") -> list[tuple[str, object]]:
    """중첩 JSON 객체를 재귀 평탄화하여 (경로, 리프값) 목록 반환."""
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

# ===========================================================================
# 차단 HTML 페이지 — SSRF 전용
# ===========================================================================

_SSRF_CATEGORY_MAP: dict[str, str] = _RULE_CATEGORY

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
  .score-bar{display:flex;align-items:center;gap:.75rem;margin-bottom:1.1rem}
  .score-label{font-size:.72rem;color:#8b9cc4;white-space:nowrap}
  .score-track{flex:1;height:8px;background:rgba(255,255,255,.08);
               border-radius:999px;overflow:hidden}
  .score-fill{height:100%;border-radius:999px;transition:width .4s}
  .score-fill.critical{background:linear-gradient(90deg,#ef4444,#dc2626)}
  .score-fill.high    {background:linear-gradient(90deg,#f97316,#ea580c)}
  .score-fill.medium  {background:linear-gradient(90deg,#eab308,#ca8a04)}
  .score-fill.low     {background:linear-gradient(90deg,#22c55e,#16a34a)}
  .score-num{font-size:.78rem;font-weight:700;color:#f0f4fc;
             min-width:3rem;text-align:right;font-variant-numeric:tabular-nums}
  .findings{background:rgba(0,0,0,.22);border:1px solid rgba(129,140,248,.15);
            border-radius:10px;overflow:hidden;margin-bottom:1.5rem}
  .finding-row{display:flex;align-items:flex-start;gap:.75rem;
               padding:.6rem .9rem;border-top:1px solid rgba(255,255,255,.04);font-size:.78rem}
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
    sorted_f = sorted(findings, key=lambda f: _SEV_RANK_BLOCK.get(f.severity, 0), reverse=True)
    for f in sorted_f:
        cat = _SSRF_CATEGORY_MAP.get(f.rule_id)
        if cat:
            return cat
    return "서버 측 요청 위조 (SSRF)"


def _max_score_from_findings(findings: tuple[Finding, ...]) -> int:
    best = 0
    for f in findings:
        try:
            part = f.evidence.split("총점:")[1].split("점")[0].strip()
            best = max(best, int(part))
        except Exception:
            pass
    return best


def make_block_html(findings: tuple[Finding, ...]) -> str:
    """SSRF 탐지 시 브라우저에 반환할 403 차단 HTML 페이지를 생성한다."""
    category  = _infer_category(findings)
    max_score = _max_score_from_findings(findings)
    top_sev   = sorted(findings, key=lambda f: _SEV_RANK_BLOCK.get(f.severity, 0), reverse=True)
    sev_label = top_sev[0].severity.value.upper() if top_sev else "HIGH"
    sev_cls   = top_sev[0].severity.value.lower() if top_sev else "high"
    bar_width = min(100, max_score)

    rows: list[str] = []
    for f in top_sev:
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
    <h1>SSRF 공격이 차단되었습니다</h1>
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
      내부 서버·클라우드 메타데이터·사설망·FTP 서버로의 요청은 허용되지 않습니다.<br>
      정상적인 요청이라면 관리자에게 문의하세요.
    </p>
    <a class="back-btn" href="javascript:history.back()">← 이전 페이지로</a>
  </div>
</body>
</html>"""

# ===========================================================================
# 공개 인터페이스 — detector.py 가 호출하는 진입점
# ===========================================================================

async def scan(ctx: RequestContext) -> ModuleScanResult:
    """A10:2025 SSRF — 요청의 모든 입력값을 검사하여 SSRF 패턴을 탐지한다.

    스캔 범위:
      URL 경로, 쿼리 파라미터(파싱+raw), JSON/Form/XML/raw 바디,
      SSRF-prone 헤더, Cookie(SSRF 키워드 쿠키명)

    FTP 탐지:
      A10-SSRF-018 (base 60): ftp:// 단독 → param_bonus 포함 시 HIGH/CRITICAL 차단
      A10-SSRF-011 (base 80): ftp://내부IP → CRITICAL 차단
    """
    all_findings: list[Finding] = []

    for label, value, rules in _collect_targets(ctx):
        all_findings.extend(_scan_value(label, value, rules))

    return ModuleScanResult(
        module_id=MODULE_ID,
        owasp_id=OWASP_ID,
        findings=_deduplicate(all_findings),
    )
