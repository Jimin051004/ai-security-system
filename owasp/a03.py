"""A03:2025 — Software Supply Chain Failures (skeleton)."""

from __future__ import annotations

from owasp.types import ModuleScanResult, RequestContext, clean_result

OWASP_ID = "A03:2025"
MODULE_ID = "a03"
TITLE = "Software Supply Chain Failures"


async def scan(ctx: RequestContext) -> ModuleScanResult:
    _ = ctx
    return clean_result(module_id=MODULE_ID, owasp_id=OWASP_ID)
