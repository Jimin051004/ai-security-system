"""A04:2025 — Server-Side Request Forgery (SSRF)

요청 파라미터, 바디, 헤더에 포함된 내부망 URL/IP 요청 패턴을 탐지한다.
OWASP A04:2025 기준 (이전 A10:2021).

탐지 유형:
  - 내부 IP 주소 참조 (127.x, 10.x, 172.16-31.x, 192.168.x)
  - 클라우드 메타데이터 엔드포인트 (169.254.169.254 등)
  - file:// / gopher:// / dict:// 등 비HTTP 스킴
  - URL 인코딩·리다이렉트를 이용한 SSRF 우회 패턴
  - Webhook/callback URL 에 내부 주소 삽입
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Sequence

from owasp.types import Finding, ModuleScanResult, RequestContext, Severity

OWASP_ID = "A04:2025"
MODULE_ID = "a04"
TITLE = "Server-Side Request Forgery (SSRF)"

# 검사 대상 파라미터 이름 (SSRF payload가 삽입될 가능성이 높은 키)
_SSRF_PARAM_HINTS = frozenset({
    "url", "uri", "src", "dest", "redirect", "redirect_uri", "return",
    "returnurl", "returnto", "next", "target", "link", "goto", "image",
    "img", "feed", "host", "webhook", "callback", "load", "fetch",
    "proxy", "request", "endpoint", "domain", "path",
})

@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str

def _r(rule_id: str, pattern: str, severity: Severity, description: str) -> _Rule:
    return _Rule(rule_id, re.compile(pattern, re.IGNORECASE | re.DOTALL), severity, description)


_RULES: tuple[_Rule, ...] = (
    # 클라우드 메타데이터 엔드포인트 (AWS/GCP/Azure)
    _r("A04-SSRF-001",
       r"169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2",
       Severity.CRITICAL, "클라우드 메타데이터 엔드포인트 접근 시도 (SSRF)"),

    # localhost / loopback
    _r("A04-SSRF-002",
       r"(?:https?://|@|%40)(?:127\.|localhost|0\.0\.0\.0|::1|%3A%3A1|%7F)",
       Severity.HIGH, "localhost/loopback 주소를 통한 SSRF 시도"),

    # RFC 1918 내부망 IP
    _r("A04-SSRF-003",
       r"(?:https?://|@|%40)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
       Severity.HIGH, "내부망 IP 주소를 통한 SSRF 시도 (RFC 1918)"),

    # 비HTTP 스킴
    _r("A04-SSRF-004",
       r"(?:^|[?&=\s])(?:file|gopher|dict|ldap|ftp|sftp|tftp|jar|netdoc|mailto)://",
       Severity.HIGH, "비HTTP 스킴을 이용한 SSRF 시도"),

    # URL 리다이렉트 파라미터 내부망 삽입
    _r("A04-SSRF-005",
       r"(?:url|redirect|next|return|goto|target|src|dest)=(?:https?://)?(?:localhost|127\.|10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.)",
       Severity.HIGH, "리다이렉트 파라미터를 통한 내부망 SSRF"),

    # IPv6 SSRF bypass (::ffff:127.0.0.1 등)
    _r("A04-SSRF-006",
       r"::ffff:(?:127\.|10\.|172\.1[6-9]\.|172\.2\d\.|192\.168\.)",
       Severity.HIGH, "IPv6 매핑 주소를 이용한 SSRF 우회"),

    # Decimal/Octal IP 표기 우회
    _r("A04-SSRF-007",
       r"https?://(?:0x7f|017700|2130706433|0177\.)",
       Severity.HIGH, "16진수/8진수 IP 표기를 이용한 SSRF 우회"),

    # DNS rebinding 지시자 패턴
    _r("A04-SSRF-008",
       r"(?:localtest\.me|spoofed\.burpcollaborator\.net|ssrf\.rebind\.|0\.0\.0\.0)",
       Severity.MEDIUM, "SSRF 테스트/DNS rebinding 도메인 패턴"),
)


def _decode_layers(value: str) -> list[str]:
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


def _is_ssrf_param(key: str) -> bool:
    return key.lower().replace("_", "").replace("-", "") in _SSRF_PARAM_HINTS


def _collect_ssrf_targets(ctx: RequestContext) -> list[tuple[str, str]]:
    targets: list[tuple[str, str]] = []

    # 쿼리 파라미터 — SSRF 관련 키 우선 검사
    if ctx.query_string:
        try:
            parsed = urllib.parse.parse_qs(ctx.query_string, keep_blank_values=True)
            for key, values in parsed.items():
                for v in values:
                    label = f"query.{key}"
                    targets.append((label, v))
                    # SSRF 힌트 키는 전체 URL 값도 추가
                    if _is_ssrf_param(key):
                        targets.append((f"ssrf_param.{key}", v))
        except Exception:
            pass

    # 바디
    if ctx.body_preview:
        targets.append(("body", ctx.body_preview))
        try:
            import json
            obj = json.loads(ctx.body_preview)
            for k, v in _flatten(obj):
                targets.append((f"body.{k}", str(v)))
        except Exception:
            pass
        # URL-encoded form
        try:
            if "application/x-www-form-urlencoded" in ctx.headers.get("content-type", ""):
                parsed_body = urllib.parse.parse_qs(ctx.body_preview, keep_blank_values=True)
                for key, values in parsed_body.items():
                    for v in values:
                        targets.append((f"form.{key}", v))
        except Exception:
            pass

    return targets


def _flatten(obj: object, prefix: str = "") -> list[tuple[str, object]]:
    items: list[tuple[str, object]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_key = f"{prefix}.{k}" if prefix else str(k)
            items.extend(_flatten(v, new_key))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            items.extend(_flatten(v, f"{prefix}[{i}]"))
    else:
        items.append((prefix, obj))
    return items


def _scan_value(value: str, *, location: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    variants = _decode_layers(value)
    for rule in _RULES:
        for variant in variants:
            m = rule.pattern.search(variant)
            if m:
                matched = m.group(0)[:200]
                findings.append(Finding(
                    rule_id=rule.rule_id,
                    evidence=f"{rule.description} | 탐지값: {matched!r}",
                    severity=rule.severity,
                    location=location,
                ))
                break
    return findings


def _deduplicate(findings: Sequence[Finding]) -> tuple[Finding, ...]:
    seen: set[str] = set()
    result: list[Finding] = []
    for f in findings:
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            result.append(f)
    return tuple(result)


async def scan(ctx: RequestContext) -> ModuleScanResult:
    """A04:2025 SSRF — 내부망 접근 패턴 탐지."""
    all_findings: list[Finding] = []
    for label, value in _collect_ssrf_targets(ctx):
        all_findings.extend(_scan_value(value, location=label))
    return ModuleScanResult(
        module_id=MODULE_ID,
        owasp_id=OWASP_ID,
        findings=_deduplicate(all_findings),
    )
