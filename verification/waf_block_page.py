"""WAF 차단 시 HTML(alert) vs JSON 응답 분기."""

from __future__ import annotations

import traffic_log
from starlette.testclient import TestClient

from main import app


def test_blocked_returns_json_when_accept_application_json() -> None:
    traffic_log.clear()
    client = TestClient(app)
    r = client.get(
        "/rest/products/search?q=test' OR '1'='1",
        headers={"Accept": "application/json"},
    )
    assert r.status_code == 403
    assert "application/json" in r.headers.get("content-type", "")
    data = r.json()
    assert data.get("blocked") is True
    assert len(data.get("findings", [])) >= 1


def test_blocked_returns_json_when_spa_fetch_accept_without_document_dest() -> None:
    """XHR/fetch: Sec-Fetch-Dest 가 document 가 아니면 JSON 403(인터셉터가 /__waf/blocked 로 이동)."""
    traffic_log.clear()
    client = TestClient(app)
    r = client.get(
        "/rest/products/search?q=test' OR '1'='1",
        headers={"Accept": "application/json, text/plain, */*"},
    )
    assert r.status_code == 403
    assert "application/json" in r.headers.get("content-type", "")
    data = r.json()
    assert data.get("blocked") is True
    assert len(data.get("findings", [])) >= 1


def test_blocked_html_when_sec_fetch_dest_omitted_but_accept_html() -> None:
    """일부 브라우저·LAN 접속 등에서 Sec-Fetch-Dest 가 없어도 Accept 가 HTML 이면 차단 페이지."""
    traffic_log.clear()
    client = TestClient(app)
    r = client.get(
        "/ftp",
        headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
    )
    assert r.status_code == 403
    assert "text/html" in r.headers.get("content-type", "")
    assert "waf_blocked.css" in r.text
    assert "wb-findings-root" in r.text


def test_blocked_returns_html_with_alert_hint_when_browser_document() -> None:
    traffic_log.clear()
    client = TestClient(app)
    r = client.get(
        "/rest/products/search?q=test' OR '1'='1",
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Sec-Fetch-Dest": "document",
        },
    )
    assert r.status_code == 403
    ct = r.headers.get("content-type", "")
    assert "text/html" in ct
    text = r.text
    assert "WAF" in text or "차단" in text
    assert "/__waf/static/css/waf_blocked.css" in text
    assert "/__waf/static/js/waf_blocked.js" in text
    assert "waf-block-boot" in text
    assert "A05:2025" in text


def test_blocked_force_html_via_query_param() -> None:
    traffic_log.clear()
    client = TestClient(app)
    r = client.get(
        "/api/x?q=test' OR '1'='1&__waf_block_format=html",
        headers={"Accept": "application/json"},
    )
    assert r.status_code == 403
    assert "text/html" in r.headers.get("content-type", "")
    assert "waf_blocked.js" in r.text
    assert "waf-block-boot" in r.text


def test_juice_shop_login_post_sql_injection_returns_json_for_interceptor() -> None:
    """로그인 XHR 은 JSON 403 — 프록시 삽입 스크립트가 /__waf/blocked 로 이동시킴(HTML 응답은 SPA 가 소스로 표시)."""
    traffic_log.clear()
    client = TestClient(app)
    r = client.post(
        "/rest/user/login",
        json={"email": "' OR 1=1--", "password": "x"},
        headers={
            "Accept": "application/json, text/plain, */*",
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/json",
        },
    )
    assert r.status_code == 403
    assert "application/json" in r.headers.get("content-type", "")
    data = r.json()
    assert data.get("blocked") is True
    assert len(data.get("findings", [])) >= 1
