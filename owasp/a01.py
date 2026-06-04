"""A01:2025 — Broken Access Control.

요청 경로·파라미터에서 접근 제어 우회, IDOR, 강제 브라우징 패턴을 탐지한다.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Sequence

from owasp.types import Finding, ModuleScanResult, RequestContext, Severity

OWASP_ID = "A01:2025"
MODULE_ID = "a01"
TITLE = "Broken Access Control"


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
        "A01-BAC-001",
        r"(?:^|/)(?:admin|administrator|manage|management|console|internal|private|superuser)(?:/|$)",
        Severity.HIGH,
        "관리자/내부 경로 강제 브라우징 시도",
    ),
    _r(
        "A01-BAC-002",
        r"(?:^|[?&])(?:user_id|userid|uid|account_id|accountId|customer_id|order_id|basket_id|role|is_admin|admin)=\d+",
        Severity.HIGH,
        "IDOR 또는 권한 파라미터 조작 의심",
    ),
    _r(
        "A01-BAC-003",
        r"(?:role|is_admin|admin|permission|privilege|access_level)=(?:admin|true|1|root|superuser)",
        Severity.CRITICAL,
        "권한 상승 파라미터 조작 시도",
    ),
    _r(
        "A01-BAC-004",
        r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c){1,}",
        Severity.HIGH,
        "경로 순회를 통한 접근 제어 우회 시도",
    ),
    _r(
        "A01-BAC-005",
        r"\b(?:x-original-url|x-rewrite-url|x-forwarded-prefix|x-forwarded-host)\b\s*[:=]\s*/?(?:admin|internal|private)",
        Severity.HIGH,
        "프록시 우회 헤더를 이용한 접근 제어 우회 시도",
    ),
)

_SAFE_BOOT_PATHS = frozenset(
    {
        # Juice Shop SPA가 초기 화면 구성에 사용하는 정상 설정 API.
        # `/admin` 직접 접근 차단은 유지하되, 이 부트스트랩 API는 통과시킨다.
        "/rest/admin/application-configuration",
    }
)


def _decode_layers(value: str) -> list[str]:
    variants = [value]
    try:
        d1 = urllib.parse.unquote(value)
        if d1 != value:
            variants.append(d1)
    except Exception:
        pass
    return variants


def _collect_targets(ctx: RequestContext) -> list[tuple[str, str]]:
    path = ctx.path or "/"
    targets: list[tuple[str, str]] = []
    if path not in _SAFE_BOOT_PATHS:
        targets.append(("path", path))
    if ctx.query_string:
        targets.append(("query", ctx.query_string))
    if ctx.body_preview:
        targets.append(("body", ctx.body_preview))
    for hdr in ("x-original-url", "x-rewrite-url", "x-forwarded-prefix", "x-forwarded-host"):
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
    seen: set[tuple[str, str | None]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.location)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return tuple(out)


async def scan(ctx: RequestContext) -> ModuleScanResult:
    findings: list[Finding] = []
    for label, value in _collect_targets(ctx):
        findings.extend(_scan_value(value, location=label))
    return ModuleScanResult(MODULE_ID, OWASP_ID, _deduplicate(findings))
