"""A01:2025 — Broken Access Control (skeleton)."""

from __future__ import annotations

from owasp.types import ModuleScanResult, RequestContext, clean_result

OWASP_ID = "A01:2025"
MODULE_ID = "a01"
TITLE = "Broken Access Control"


async def scan(ctx: RequestContext) -> ModuleScanResult:
    _ = ctx
    return clean_result(module_id=MODULE_ID, owasp_id=OWASP_ID)
