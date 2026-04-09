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

    # X-Forwarded-For / X-Real-IP 가 없으면 실제 소켓 IP 를 주입한다.
    # 이 덕분에 OWASP 모듈의 _get_client_ip() 가 "unknown" 대신 정확한 IP를
    # 반환하여 브루트포스·레이트 리밋 등 IP별 추적 규칙이 올바르게 동작한다.
    if "x-forwarded-for" not in headers and "x-real-ip" not in headers:
        if request.client and request.client.host:
            headers = dict(headers)          # 불변 MutableHeaders 복사
            headers["x-real-ip"] = request.client.host

    path = request.url.path or "/"
    query = request.url.query or ""
    return RequestContext(
        method=request.method.upper(),
        path=path,
        query_string=query,
        headers=headers,
        body_preview=preview,
    )
