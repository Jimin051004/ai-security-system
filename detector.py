"""Run all OWASP Top 10:2025 modules against a request snapshot."""

from __future__ import annotations

from owasp import MODULES
from owasp.types import Finding, ModuleScanResult, RequestContext


async def scan_request(ctx: RequestContext) -> list[ModuleScanResult]:
    return [await mod.scan(ctx) for mod in MODULES]


def all_findings(results: list[ModuleScanResult]) -> list[Finding]:
    out: list[Finding] = []
    for r in results:
        out.extend(r.findings)
    return out
