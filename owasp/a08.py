"""A08:2025 — Software or Data Integrity Failures (skeleton)."""

from __future__ import annotations

from owasp.types import ModuleScanResult, RequestContext, clean_result

OWASP_ID = "A08:2025"
MODULE_ID = "a08"
TITLE = "Software or Data Integrity Failures"


async def scan(ctx: RequestContext) -> ModuleScanResult:
    _ = ctx
    return clean_result(module_id=MODULE_ID, owasp_id=OWASP_ID)
