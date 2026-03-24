"""A02:2025 — Security Misconfiguration (skeleton)."""

from __future__ import annotations

from owasp.types import ModuleScanResult, RequestContext, clean_result

OWASP_ID = "A02:2025"
MODULE_ID = "a02"
TITLE = "Security Misconfiguration"


async def scan(ctx: RequestContext) -> ModuleScanResult:
    _ = ctx
    return clean_result(module_id=MODULE_ID, owasp_id=OWASP_ID)
