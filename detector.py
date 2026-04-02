"""Run all OWASP Top 10:2025 modules against a request snapshot."""

from __future__ import annotations

from owasp import MODULES
from owasp.types import Finding, ModuleScanResult, RequestContext, Severity

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.NONE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


async def scan_request(ctx: RequestContext) -> list[ModuleScanResult]:
    return [await mod.scan(ctx) for mod in MODULES]


def all_findings(results: list[ModuleScanResult]) -> list[Finding]:
    out: list[Finding] = []
    for r in results:
        out.extend(r.findings)
    return out


def findings_at_or_above_severity(
    findings: list[Finding],
    min_severity: Severity,
) -> list[Finding]:
    """Findings that meet or exceed the configured block threshold."""
    threshold = _SEVERITY_RANK[min_severity]
    return [f for f in findings if _SEVERITY_RANK[f.severity] >= threshold]


def waf_blocking_findings(
    findings: list[Finding],
    min_severity: Severity,
) -> list[Finding]:
    """WAF 차단 대상: `min_severity` 이상 + OWASP A05 인젝션(`A05-*` rule_id)은 심각도와 무관하게 포함."""
    base = findings_at_or_above_severity(findings, min_severity)

    def _key(f: Finding) -> tuple[str, str]:
        return (f.rule_id, f.location or "")

    seen = {_key(f) for f in base}
    out = list(base)
    for f in findings:
        if not f.rule_id.upper().startswith("A05-"):
            continue
        k = _key(f)
        if k in seen:
            continue
        seen.add(k)
        out.append(f)
    return out


def parse_severity(name: str, default: Severity = Severity.HIGH) -> Severity:
    key = (name or "").strip().lower()
    if not key:
        return default
    try:
        return Severity(key)
    except ValueError:
        return default
