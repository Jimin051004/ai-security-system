"""Map any incoming HTTP request to OWASP RequestContext (upstream-agnostic)."""

from __future__ import annotations

from starlette.requests import Request

from owasp.types import RequestContext

DEFAULT_BODY_PREVIEW_MAX = 8192


async def request_to_context(
    request: Request,
    *,
    body_preview_max: int = DEFAULT_BODY_PREVIEW_MAX,
) -> RequestContext:
    """Read body once (Starlette caches it for later handlers)."""
    body = await request.body()
    preview = body[:body_preview_max].decode("utf-8", errors="replace")
    headers = {k: v for k, v in request.headers.items()}
    path = request.url.path or "/"
    query = request.url.query or ""
    return RequestContext(
        method=request.method.upper(),
        path=path,
        query_string=query,
        headers=headers,
        body_preview=preview,
    )
