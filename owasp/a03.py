"""A03:2025 — Software Supply Chain Failures.

외부 스크립트/패키지 로딩 조작, dependency confusion, 무결성 없는 CDN 리소스 힌트를 탐지한다.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Sequence

from owasp.types import Finding, ModuleScanResult, RequestContext, Severity

OWASP_ID = "A03:2025"
MODULE_ID = "a03"
TITLE = "Software Supply Chain Failures"


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
        "A03-SUPPLY-001",
        r"(?:^|[?&])(?:script|src|cdn|asset|module|package|dependency|lib)=https?://(?:raw\.githubusercontent\.com|gist\.github\.com|pastebin\.com|cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com)/",
        Severity.HIGH,
        "외부 패키지/CDN 리소스 주입 시도",
    ),
    _r(
        "A03-SUPPLY-002",
        r"(?:npm|pip|gem|maven|composer|cargo)(?:_|\-)?(?:package|module|dependency)?\s*=\s*(?:@?[\w.-]+/)?(?:test|internal|private|company|corp)[\w.-]*",
        Severity.HIGH,
        "dependency confusion 의심 패키지명 입력",
    ),
    _r(
        "A03-SUPPLY-003",
        r"(?:package(?:-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|requirements\.txt|pom\.xml|build\.gradle|composer\.lock)(?:$|[?#])",
        Severity.HIGH,
        "의존성/빌드 메타데이터 파일 접근 시도",
    ),
    _r(
        "A03-SUPPLY-004",
        r"<script[^>]+src=['\"]https?://[^'\"]+['\"][^>]*(?!integrity=)",
        Severity.MEDIUM,
        "무결성 속성 없는 외부 스크립트 삽입 패턴",
    ),
    _r(
        "A03-SUPPLY-005",
        r"(?:curl|wget)\s+https?://[^|;&]+[|;]\s*(?:sh|bash|powershell|pwsh)",
        Severity.CRITICAL,
        "원격 설치 스크립트 파이프 실행 패턴",
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
    for hdr in ("referer", "origin"):
        val = ctx.headers.get(hdr, "")
        if val:
            targets.append((f"header.{hdr}", val))
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
