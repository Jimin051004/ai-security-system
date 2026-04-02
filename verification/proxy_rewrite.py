"""프록시 응답에서 업스트림 절대 URL → 클라이언트가 접속한 호스트로 치환."""

from __future__ import annotations

import httpx
from starlette.requests import Request

from main import (
    _build_proxied_upstream_response,
    _rewrite_location_header,
    _rewrite_response_body_for_public_origin,
)


def _req(host: str, port: int) -> Request:
    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": [(b"host", f"{host}:{port}".encode())],
            "client": ("192.168.1.10", 2222),
            "server": (host, port),
        }
    )


def test_rewrite_location_to_public_origin() -> None:
    req = _req("192.168.0.39", 8080)
    assert _rewrite_location_header("http://127.0.0.1:3001/rest/user/1", req) == (
        "http://192.168.0.39:8080/rest/user/1"
    )


def test_rewrite_html_embedded_upstream_origin() -> None:
    req = _req("192.168.0.39", 8080)
    raw = b'<script src="http://127.0.0.1:3001/main.js"></script>'
    out, _ = _rewrite_response_body_for_public_origin(raw, "text/html; charset=utf-8", req)
    assert b"192.168.0.39:8080" in out
    assert b"127.0.0.1:3001" not in out


def test_proxied_html_strips_csp_when_interceptor_injected() -> None:
    """업스트림 CSP 가 인라인을 막을 수 있어, 인터셉터 주입 시 CSP 헤더는 제거한다."""
    req = _req("192.168.0.39", 8080)
    upstream = httpx.Response(
        200,
        headers=[
            ("Content-Type", "text/html; charset=utf-8"),
            ("Content-Security-Policy", "default-src 'self'"),
        ],
        content=b"<!DOCTYPE html><html><head></head><body>x</body></html>",
    )
    resp = _build_proxied_upstream_response(req, upstream)
    assert resp.status_code == 200
    assert b"waf_proxy_interceptor.js" in resp.body
    h = {k.decode().lower(): v.decode() for k, v in resp.raw_headers}
    assert "content-security-policy" not in h


def test_build_proxied_response_does_not_use_list_headers() -> None:
    """Starlette Response 는 list 헤더 시 500 — MutableHeaders 로 감싼다."""
    req = _req("192.168.0.39", 8080)
    upstream = httpx.Response(
        200,
        headers=[("Content-Type", "text/plain; charset=utf-8"), ("Set-Cookie", "a=1")],
        content=b"ok",
    )
    resp = _build_proxied_upstream_response(req, upstream)
    assert resp.status_code == 200
    assert resp.body == b"ok"
