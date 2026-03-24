"""A10:2025 — Mishandling of Exceptional Conditions (skeleton)."""

from __future__ import annotations

from owasp.types import ModuleScanResult, RequestContext, clean_result

OWASP_ID = "A10:2025"
MODULE_ID = "a10"
TITLE = "Mishandling of Exceptional Conditions"


async def scan(ctx: RequestContext) -> ModuleScanResult:
    _ = ctx
    return clean_result(module_id=MODULE_ID, owasp_id=OWASP_ID)
