"""Minimal reverse proxy: client → this app → UPSTREAM (e.g. Juice Shop)."""

from __future__ import annotations

import os
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Request, Response

UPSTREAM_RAW = os.environ.get("UPSTREAM_URL", "http://127.0.0.1:3001").rstrip("/")
_parsed = urlparse(UPSTREAM_RAW)
if not _parsed.scheme or not _parsed.netloc:
    raise SystemExit("UPSTREAM_URL must be a full URL, e.g. http://127.0.0.1:3001")

UPSTREAM_BASE = UPSTREAM_RAW
UPSTREAM_HOST_HEADER = _parsed.netloc

HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
    }
)

app = FastAPI(title="AI Security System", description="Reverse proxy to upstream web app")

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]


def _upstream_headers(request: Request) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in request.headers.items():
        if key.lower() in HOP_BY_HOP:
            continue
        out[key] = value
    out["host"] = UPSTREAM_HOST_HEADER
    return out


async def _forward(request: Request, full_path: str) -> Response:
    path = full_path.lstrip("/")
    url = f"{UPSTREAM_BASE}/{path}" if path else UPSTREAM_BASE
    if request.url.query:
        url = f"{url}?{request.url.query}"

    body = await request.body()
    headers = _upstream_headers(request)

    async with httpx.AsyncClient(follow_redirects=False) as client:
        try:
            upstream = await client.request(
                request.method,
                url,
                headers=headers,
                content=body if body else None,
                timeout=httpx.Timeout(60.0),
            )
        except httpx.RequestError as exc:
            return Response(
                content=f"Upstream unreachable: {exc}".encode(),
                status_code=502,
                media_type="text/plain; charset=utf-8",
            )

    out_headers = {
        k: v
        for k, v in upstream.headers.items()
        if k.lower() not in HOP_BY_HOP and k.lower() != "content-length"
    }
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=dict(out_headers),
    )


@app.get("/__proxy/health")
async def proxy_health() -> dict[str, str]:
    return {"status": "ok", "upstream": UPSTREAM_BASE}


@app.api_route("/", methods=METHODS)
async def proxy_root(request: Request) -> Response:
    return await _forward(request, "")


@app.api_route("/{full_path:path}", methods=METHODS)
async def proxy_path(full_path: str, request: Request) -> Response:
    # Reserve /__proxy/* for this app (e.g. GET /__proxy/health is registered above).
    if full_path == "__proxy" or full_path.startswith("__proxy/"):
        return Response(status_code=404)
    return await _forward(request, full_path)
