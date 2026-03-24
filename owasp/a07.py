"""A07:2025 — Authentication Failures (skeleton)."""

from __future__ import annotations

from owasp.types import ModuleScanResult, RequestContext, clean_result

OWASP_ID = "A07:2025"
MODULE_ID = "a07"
TITLE = "Authentication Failures"


async def scan(ctx: RequestContext) -> ModuleScanResult:
    _ = ctx
    return clean_result(module_id=MODULE_ID, owasp_id=OWASP_ID)
