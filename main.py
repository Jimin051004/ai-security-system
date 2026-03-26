"""Reverse proxy: client → WAF scan → UPSTREAM (any origin via UPSTREAM_URL)."""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from detector import (
    all_findings,
    findings_at_or_above_severity,
    parse_severity,
    scan_request,
)
from owasp.types import Severity
from request_snapshot import DEFAULT_BODY_PREVIEW_MAX, request_to_context

UPSTREAM_RAW = os.environ.get("UPSTREAM_URL", "http://127.0.0.1:3001").rstrip("/")
_parsed = urlparse(UPSTREAM_RAW)
if not _parsed.scheme or not _parsed.netloc:
    raise SystemExit("UPSTREAM_URL must be a full URL, e.g. http://127.0.0.1:3001")

UPSTREAM_BASE = UPSTREAM_RAW
UPSTREAM_HOST_HEADER = _parsed.netloc


def _waf_enabled() -> bool:
    v = os.environ.get("WAF_ENABLED", "true").strip().lower()
    return v not in ("0", "false", "no", "off")


def _waf_block_min_severity() -> Severity:
    return parse_severity(os.environ.get("WAF_BLOCK_MIN_SEVERITY", "high"), Severity.HIGH)


def _body_preview_max() -> int:
    raw = os.environ.get("WAF_BODY_PREVIEW_MAX", "").strip()
    if not raw:
        return DEFAULT_BODY_PREVIEW_MAX
    try:
        return max(256, min(int(raw), 1024 * 1024))
    except ValueError:
        return DEFAULT_BODY_PREVIEW_MAX


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


def _finding_to_json(f) -> dict[str, str]:
    ev = f.evidence
    if len(ev) > 500:
        ev = ev[:500] + "…"
    return {"rule_id": f.rule_id, "severity": f.severity.value, "evidence": ev}


async def _waf_response_or_none(request: Request) -> Response | None:
    """Run OWASP modules; return 403 JSON if policy says block, else None (allow)."""
    if not _waf_enabled():
        return None
    ctx = await request_to_context(request, body_preview_max=_body_preview_max())
    results = await scan_request(ctx)
    findings = all_findings(results)
    min_sev = _waf_block_min_severity()
    blocking = findings_at_or_above_severity(findings, min_sev)
    if not blocking:
        return None
    payload = {
        "blocked": True,
        "policy": "min_severity",
        "min_severity": min_sev.value,
        "upstream": UPSTREAM_BASE,
        "findings": [_finding_to_json(f) for f in blocking],
    }
    return JSONResponse(status_code=403, content=payload)


@app.get("/__proxy/health")
async def proxy_health() -> dict[str, Any]:
    return {
        "status": "ok",
        "upstream": UPSTREAM_BASE,
        "waf_enabled": _waf_enabled(),
        "waf_block_min_severity": _waf_block_min_severity().value,
    }


@app.api_route("/", methods=METHODS)
async def proxy_root(request: Request) -> Response:
    blocked = await _waf_response_or_none(request)
    if blocked is not None:
        return blocked
    return await _forward(request, "")


@app.api_route("/{full_path:path}", methods=METHODS)
async def proxy_path(full_path: str, request: Request) -> Response:
    # Reserve /__proxy/* for this app (e.g. GET /__proxy/health is registered above).
    if full_path == "__proxy" or full_path.startswith("__proxy/"):
        return Response(status_code=404)
    blocked = await _waf_response_or_none(request)
    if blocked is not None:
        return blocked
    return await _forward(request, full_path)
