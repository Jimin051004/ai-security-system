"""A09:2025 — Security Logging and Alerting Failures.

로그 회피, 추적 방해, 알림 우회 목적의 요청 패턴을 탐지한다.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Sequence

from owasp.types import Finding, ModuleScanResult, RequestContext, Severity

OWASP_ID = "A09:2025"
MODULE_ID = "a09"
TITLE = "Security Logging and Alerting Failures"


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
        "A09-LOG-001",
        r"(?:%0d%0a|%0a|%0d|\\r\\n|\\n).{0,80}(?:error|warn|info|debug|trace|admin|login|blocked)",
        Severity.HIGH,
        "로그 인젝션/줄바꿈 삽입 시도",
    ),
    _r(
        "A09-LOG-002",
        r"(?:^|[?&])(?:log|logging|audit|alert|trace|monitor|telemetry)=(?:0|false|off|none|disable|disabled)",
        Severity.HIGH,
        "로깅/알림 비활성화 파라미터 조작",
    ),
    _r(
        "A09-LOG-003",
        r"(?:x-forwarded-for|x-real-ip|forwarded)\s*[:=]\s*(?:unknown|127\.0\.0\.1|0\.0\.0\.0|10\.|192\.168\.|,|;)",
        Severity.MEDIUM,
        "클라이언트 IP 추적 방해 헤더",
    ),
    _r(
        "A09-LOG-004",
        r"(?:user-agent|referer)\s*[:=]\s*.{0,120}(?:sqlmap|nmap|nikto|acunetix|burp|zap|masscan|dirbuster)",
        Severity.HIGH,
        "자동화 공격 도구 흔적",
    ),
    _r(
        "A09-LOG-005",
        r"[\x00-\x08\x0b\x0c\x0e-\x1f]{3,}",
        Severity.HIGH,
        "제어문자 반복을 통한 로그 파싱 방해",
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
    for hdr in ("x-forwarded-for", "x-real-ip", "forwarded", "user-agent", "referer"):
        val = ctx.headers.get(hdr, "")
        if val:
            targets.append((f"header.{hdr}", f"{hdr}: {val}"))
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
