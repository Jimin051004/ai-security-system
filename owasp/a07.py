"""A07:2025 — Authentication Failures.

브루트포스, 기본 계정, JWT/세션 조작 등 인증 실패 패턴을 요청 단위로 탐지한다.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Sequence

from owasp.types import Finding, ModuleScanResult, RequestContext, Severity

OWASP_ID = "A07:2025"
MODULE_ID = "a07"
TITLE = "Authentication Failures"


@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str


def _r(rule_id: str, pattern: str, severity: Severity, description: str) -> _Rule:
    return _Rule(rule_id, re.compile(pattern, re.IGNORECASE | re.DOTALL), severity, description)


_RULES: tuple[_Rule, ...] = (
    _r(
        "A07-AUTH-001",
        r"(?:^|/)(?:login|signin|auth|session|token)(?:/|$|[?#]).*(?:username|email|user)=(?:admin|root|test|guest)&(?:password|pass|pwd)=(?:admin|password|123456|1234|test|guest)",
        Severity.HIGH,
        "기본/약한 인증정보 로그인 시도",
    ),
    _r(
        "A07-AUTH-002",
        r"(?:password|pass|pwd)=(?:admin|password|123456|12345678|qwerty|letmein|welcome|iloveyou)",
        Severity.HIGH,
        "취약 비밀번호 기반 크리덴셜 스터핑 의심",
    ),
    _r(
        "A07-AUTH-003",
        r"eyJ[^.\s]+\.eyJ[^.\s]+\.[A-Za-z0-9_-]*",
        Severity.MEDIUM,
        "JWT 토큰 직접 전달/조작 의심",
    ),
    _r(
        "A07-AUTH-004",
        r"alg[\"']?\s*[:=]\s*[\"']?none[\"']?",
        Severity.CRITICAL,
        "JWT alg=none 우회 시도",
    ),
    _r(
        "A07-AUTH-005",
        r"(?:session|sid|token|jwt|auth)=.{0,30}(?:null|undefined|guest|anonymous|debug|bypass)",
        Severity.HIGH,
        "세션/토큰 우회 값 사용 시도",
    ),
)


def _decode_layers(value: str) -> list[str]:
    variants = [value]
    try:
        d1 = urllib.parse.unquote_plus(value)
        if d1 != value:
            variants.append(d1)
    except Exception:
        pass
    return variants


def _collect_targets(ctx: RequestContext) -> list[tuple[str, str]]:
    targets = [("path", ctx.path or "/")]
    if ctx.query_string:
        targets.append(("query", ctx.query_string))
    if ctx.body_preview:
        targets.append(("body", ctx.body_preview))
    for hdr in ("authorization", "cookie"):
        val = ctx.headers.get(hdr, "")
        if val:
            targets.append((f"header.{hdr}", val[:2048]))
    return targets


def _scan_value(value: str, *, location: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for rule in _RULES:
        for variant in _decode_layers(value):
            m = rule.pattern.search(variant)
            if m:
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        evidence=f"{rule.description} | 탐지값: {m.group(0)[:200]!r}",
                        severity=rule.severity,
                        location=location,
                    )
                )
                break
    return findings


def _deduplicate(findings: Sequence[Finding]) -> tuple[Finding, ...]:
    seen: set[str] = set()
    out: list[Finding] = []
    for f in findings:
        if f.rule_id in seen:
            continue
        seen.add(f.rule_id)
        out.append(f)
    return tuple(out)


async def scan(ctx: RequestContext) -> ModuleScanResult:
    findings: list[Finding] = []
    for label, value in _collect_targets(ctx):
        findings.extend(_scan_value(value, location=label))
    return ModuleScanResult(MODULE_ID, OWASP_ID, _deduplicate(findings))
