"""A05:2025 — Injection (skeleton; implement signatures here first)."""

from __future__ import annotations

from owasp.types import ModuleScanResult, RequestContext, clean_result

OWASP_ID = "A05:2025"
MODULE_ID = "a05"
TITLE = "Injection"


async def scan(ctx: RequestContext) -> ModuleScanResult:
    _ = ctx
    return clean_result(module_id=MODULE_ID, owasp_id=OWASP_ID)
