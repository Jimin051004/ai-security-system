"""Reverse proxy: client → WAF scan → UPSTREAM (any origin via UPSTREAM_URL)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import jinja2
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from detector import (
    all_findings,
    findings_at_or_above_severity,
    parse_severity,
    scan_request,
)
from owasp.types import Severity
from request_snapshot import DEFAULT_BODY_PREVIEW_MAX, request_to_context

import traffic_log

UPSTREAM_RAW = os.environ.get("UPSTREAM_URL", "http://127.0.0.1:3001").rstrip("/")
_parsed = urlparse(UPSTREAM_RAW)
if not _parsed.scheme or not _parsed.netloc:
    raise SystemExit("UPSTREAM_URL must be a full URL, e.g. http://127.0.0.1:3001")

UPSTREAM_BASE = UPSTREAM_RAW
UPSTREAM_HOST_HEADER = _parsed.netloc
UPSTREAM_ORIGIN = f"{_parsed.scheme}://{_parsed.netloc}".rstrip("/")

# LAN 등에서 클라이언트가 프록시 호스트(예: 192.168.x.x:8080)로 접속할 때,
# 업스트림 HTML/JS에 박힌 http://127.0.0.1:3001 절대 URL 때문에 브라우저가 로컬로 요청하는 문제 방지
PROXY_REWRITE_MAX_BYTES = int(os.environ.get("PROXY_REWRITE_MAX_BYTES", str(6 * 1024 * 1024)))


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
_BASE = Path(__file__).resolve().parent
_jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(_BASE / "templates")),
    autoescape=jinja2.select_autoescape(["html", "xml"]),
)

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

# Juice Shop 등 업스트림에도 /dashboard·/api/... 가 있어 catch-all에 먹히면 프록시 UI 대신 업스트림이 뜸.
# 프록시 전용 UI는 항상 이 접두사(및 아래 예외 경로)로만 노출.
WAF_UI_PREFIX = "/__waf"


def _normalize_proxy_path_segment(full_path: str) -> str:
    """catch-all 에서 온 하위 경로 정규화 (끝 슬래시·대소문자 비교용)."""
    return (full_path or "").strip().rstrip("/")


def _is_waf_dashboard_path(norm: str) -> bool:
    n = norm.casefold()
    return n == "dashboard" or n == "__waf/dashboard"


def _is_waf_summary_api_path(norm: str) -> bool:
    n = norm.casefold()
    return n in ("api/dashboard/summary", "__waf/api/summary")


async def _probe_upstream() -> tuple[bool, str]:
    """업스트림에 연결 가능한지 확인(404 등은 서버가 살아 있는 것으로 간주, 5xx·연결 실패만 불량)."""
    timeout = httpx.Timeout(3.0)
    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            r = await client.head(UPSTREAM_BASE, timeout=timeout)
            if r.status_code == 405:
                r = await client.get(UPSTREAM_BASE, timeout=timeout)
            ok = r.status_code < 500
            return (ok, "" if ok else f"HTTP {r.status_code}")
    except httpx.HTTPError as exc:
        return (False, str(exc)[:200])
    except OSError as exc:
        return (False, str(exc)[:200])


def _dashboard_summary_dict(*, upstream_ok: bool, upstream_error: str) -> dict[str, Any]:
    return {
        "status": "ok",
        "upstream": UPSTREAM_BASE,
        "upstream_ok": upstream_ok,
        "upstream_error": upstream_error,
        "waf_enabled": _waf_enabled(),
        "waf_block_min_severity": _waf_block_min_severity().value,
        "body_preview_max": _body_preview_max(),
    }


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    rip = request.headers.get("x-real-ip")
    if rip:
        return rip.strip()
    if request.client:
        return request.client.host or "—"
    return "—"


def _access_snapshot(request: Request) -> dict[str, Any]:
    u = request.url
    return {
        "client_ip": _client_ip(request),
        "x_forwarded_for": request.headers.get("x-forwarded-for") or "",
        "x_real_ip": request.headers.get("x-real-ip") or "",
        "user_agent": request.headers.get("user-agent") or "—",
        "method": request.method,
        "path": u.path,
        "full_url": str(u),
        "host_header": request.headers.get("host") or "—",
        "referer": request.headers.get("referer") or "—",
        "accept_language": request.headers.get("accept-language") or "—",
    }


def _upstream_headers(request: Request) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in request.headers.items():
        if key.lower() in HOP_BY_HOP:
            continue
        out[key] = value
    out["host"] = UPSTREAM_HOST_HEADER
    return out


def _request_public_origin(request: Request) -> str:
    u = request.url
    return f"{u.scheme}://{u.netloc}".rstrip("/")


def _upstream_origin_variants() -> list[str]:
    """UPSTREAM_URL 과 같은 서버를 가리키는 localhost / 127.0.0.1 표기 (SPA 번들·리다이렉트에 섞임)."""
    variants = [UPSTREAM_ORIGIN]
    host = (_parsed.hostname or "").lower()
    scheme = (_parsed.scheme or "http").lower()
    port = _parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80
    if host in ("127.0.0.1", "localhost"):
        alt = "localhost" if host == "127.0.0.1" else "127.0.0.1"
        variants.append(f"{scheme}://{alt}:{port}")
    out: list[str] = []
    seen: set[str] = set()
    for v in variants:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _rewrite_location_header(value: str, request: Request) -> str:
    pub = _request_public_origin(request)
    v = (value or "").strip()
    for orig in sorted(_upstream_origin_variants(), key=len, reverse=True):
        if v.startswith(orig):
            return pub + v[len(orig) :]
    return value


def _media_type_should_rewrite_body(ct_header: str) -> bool:
    main = (ct_header or "").split(";")[0].strip().lower()
    if main in ("text/html", "application/json", "text/css"):
        return True
    if "javascript" in main or "ecmascript" in main:
        return True
    return False


def _rewrite_response_body_for_public_origin(
    content: bytes, content_type: str, request: Request
) -> bytes:
    if len(content) > PROXY_REWRITE_MAX_BYTES:
        return content
    if not _media_type_should_rewrite_body(content_type):
        return content
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return content
    pub = _request_public_origin(request)
    changed = False
    for orig in sorted(_upstream_origin_variants(), key=len, reverse=True):
        if orig in text:
            text = text.replace(orig, pub)
            changed = True
    if not changed:
        return content
    return text.encode("utf-8")


def _build_proxied_upstream_response(request: Request, upstream: httpx.Response) -> Response:
    ct = upstream.headers.get("content-type", "")
    content = _rewrite_response_body_for_public_origin(upstream.content, ct, request)
    out: list[tuple[str, str]] = []
    for key, value in upstream.headers.multi_items():
        lk = key.lower()
        if lk in HOP_BY_HOP:
            continue
        if lk in ("content-length", "content-encoding", "transfer-encoding"):
            continue
        if lk == "location":
            value = _rewrite_location_header(value, request)
        out.append((key, value))
    return Response(
        content=content,
        status_code=upstream.status_code,
        headers=out,
    )


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

    return _build_proxied_upstream_response(request, upstream)


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
        "dashboard_path": f"{WAF_UI_PREFIX}/dashboard",
    }


async def api_dashboard_summary(request: Request | None = None) -> dict[str, Any]:
    up_ok, up_err = await _probe_upstream()
    out = _dashboard_summary_dict(upstream_ok=up_ok, upstream_error=up_err)
    if request is not None:
        out["access"] = _access_snapshot(request)
    return out


async def dashboard_page(request: Request) -> HTMLResponse:
    initial = await api_dashboard_summary(request)
    tpl = _jinja_env.get_template("dashboard.html")
    html = tpl.render(
        upstream=UPSTREAM_BASE,
        boot=initial,
    )
    return HTMLResponse(
        html,
        headers={
            # 같은 출처에서 업스트림(SPA) SW가 오래된 index를 쓰는 일을 줄임
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
        },
    )


@app.get("/__waf/dashboard")
async def waf_dashboard_canonical(request: Request) -> HTMLResponse:
    return await dashboard_page(request)


@app.get("/__waf/api/summary")
async def waf_api_summary_canonical(request: Request) -> dict[str, Any]:
    return await api_dashboard_summary(request)


@app.get("/__waf/api/traffic")
async def waf_api_traffic() -> dict[str, Any]:
    events = await traffic_log.snapshot_dicts()
    return {"status": "ok", "events": events}


@app.get("/__waf/api/clients")
async def waf_api_clients() -> dict[str, Any]:
    return await traffic_log.clients_snapshot()


# `/__waf/{waf_tail:path}` 보다 먼저 등록해야 정적 파일이 404로 가지 않음
_WAF_STATIC_DIR = _BASE / "static" / "waf"
app.mount(
    "/__waf/static",
    StaticFiles(directory=str(_WAF_STATIC_DIR)),
    name="waf_static",
)


def _waf_unknown_path_response() -> JSONResponse:
    """`/__waf/*` 중 대시보드·요약 API가 아닌 경로 — 업스트림으로 넘기면 Juice Shop HTML이 먹힘."""
    return JSONResponse(
        status_code=404,
        content={"detail": "Unknown WAF UI path; use /__waf/dashboard"},
        headers={"Cache-Control": "no-store"},
    )


@app.api_route("/__waf", methods=METHODS)
@app.api_route("/__waf/", methods=METHODS)
async def waf_prefix_only_reserved(_request: Request) -> JSONResponse:
    return _waf_unknown_path_response()


# catch-all `/{full_path:path}` 보다 먼저 매칭되게 해 `__waf/scripts.js` 등이 업스트림으로 가지 않도록 함
@app.api_route("/__waf/{waf_tail:path}", methods=METHODS)
async def waf_unknown_subpath(waf_tail: str, _request: Request) -> JSONResponse:
    return _waf_unknown_path_response()


@app.get("/api/dashboard/summary")
async def api_dashboard_summary_legacy(request: Request) -> dict[str, Any]:
    return await api_dashboard_summary(request)


@app.get("/dashboard")
async def dashboard_legacy_redirect() -> RedirectResponse:
    return RedirectResponse(url=f"{WAF_UI_PREFIX}/dashboard", status_code=307)


@app.get("/dashboard/")
async def dashboard_legacy_redirect_slash() -> RedirectResponse:
    return RedirectResponse(url=f"{WAF_UI_PREFIX}/dashboard", status_code=307)


@app.api_route("/", methods=METHODS)
async def proxy_root(request: Request) -> Response:
    blocked = await _waf_response_or_none(request)
    if blocked is not None:
        await traffic_log.record(request, status_code=403, blocked=True)
        return blocked
    resp = await _forward(request, "")
    await traffic_log.record(request, status_code=resp.status_code, blocked=False)
    return resp


@app.api_route("/{full_path:path}", methods=METHODS)
async def proxy_path(full_path: str, request: Request) -> Response:
    # Reserve /__proxy/*
    if full_path == "__proxy" or full_path.startswith("__proxy/"):
        return Response(status_code=404)
    # catch-all 이 정적 라우트보다 먼저 잡히는 경우 → 업스트림 /dashboard 대신 프록시 UI
    norm = _normalize_proxy_path_segment(full_path)
    if request.method == "GET" and _is_waf_dashboard_path(norm):
        return await dashboard_page(request)
    if request.method == "GET" and _is_waf_summary_api_path(norm):
        return await api_dashboard_summary(request)
    # /__waf/* 는 위의 전용 라우트에서 처리; 여기는 예외 경로만 안전망
    if full_path == "__waf" or full_path.startswith("__waf/"):
        return _waf_unknown_path_response()
    blocked = await _waf_response_or_none(request)
    if blocked is not None:
        await traffic_log.record(request, status_code=403, blocked=True)
        return blocked
    resp = await _forward(request, full_path)
    await traffic_log.record(request, status_code=resp.status_code, blocked=False)
    return resp
