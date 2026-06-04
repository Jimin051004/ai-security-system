"""A02:2025 — Security Misconfiguration.

민감 파일, 디버그 엔드포인트, 기본 콘솔, 설정 노출 요청을 탐지한다.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Sequence

from owasp.types import Finding, ModuleScanResult, RequestContext, Severity

OWASP_ID = "A02:2025"
MODULE_ID = "a02"
TITLE = "Security Misconfiguration"


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
        "A02-CONFIG-001",
        r"(?:^|/)\.(?:env|git|svn|hg|DS_Store)(?:/|$|[?#])|(?:^|/)(?:config|settings|application|database)\.(?:ya?ml|json|ini|properties|php)(?:$|[?#])",
        Severity.CRITICAL,
        "민감 설정 파일 또는 VCS 메타데이터 접근 시도",
    ),
    _r(
        "A02-CONFIG-002",
        r"(?:^|/)(?:debug|actuator|actuator/env|actuator/heapdump|server-status|phpinfo|jolokia|metrics|swagger-ui|api-docs)(?:/|$|[?#])",
        Severity.HIGH,
        "디버그/운영 관리 엔드포인트 노출 접근 시도",
    ),
    _r(
        "A02-CONFIG-003",
        r"(?:^|/)(?:backup|backups|dump|dbdump|sql|old|bak)(?:/|$)|\.(?:bak|old|backup|sql|dump|tar|tgz|zip)(?:$|[?#])",
        Severity.HIGH,
        "백업/덤프 파일 노출 접근 시도",
    ),
    _r(
        "A02-CONFIG-004",
        r"(?:^|[?&])(?:debug|trace|verbose|show_errors|display_errors|test|dev)=(?:1|true|yes|on)",
        Severity.HIGH,
        "디버그 모드 강제 활성화 파라미터",
    ),
    _r(
        "A02-CONFIG-005",
        r"(?:^|/)(?:wp-admin/setup-config\.php|install\.php|setup|setup-wizard|adminer\.php|phpmyadmin)(?:/|$|[?#])",
        Severity.HIGH,
        "기본 설치/관리 도구 접근 시도",
    ),
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
    targets = [("path", ctx.path or "/")]
    if ctx.query_string:
        targets.append(("query", ctx.query_string))
    if ctx.body_preview:
        targets.append(("body", ctx.body_preview))
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
