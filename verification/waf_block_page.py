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


def test_blocked_returns_html_when_accept_json_plus_wildcard_like_spa_fetch() -> None:
    """Juice Shop 등 SPA: Accept에 json이 먼저 와도 */*·text/plain이면 HTML 차단 페이지."""
    traffic_log.clear()
    client = TestClient(app)
    r = client.get(
        "/rest/products/search?q=test' OR '1'='1",
        headers={"Accept": "application/json, text/plain, */*"},
    )
    assert r.status_code == 403
    assert "text/html" in r.headers.get("content-type", "")
    assert "waf_blocked.js" in r.text


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
