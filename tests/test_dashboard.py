"""웹 대시보드·요약 API."""

from __future__ import annotations

from starlette.testclient import TestClient

from main import app


def test_dashboard_page_200() -> None:
    client = TestClient(app)
    r = client.get("/dashboard")
    assert r.status_code == 200
    assert "AI Security System" in r.text
    assert "업스트림" in r.text


def test_api_dashboard_summary_json() -> None:
    client = TestClient(app)
    r = client.get("/api/dashboard/summary")
    assert r.status_code == 200
    data = r.json()
    assert "upstream" in data
    assert "waf_enabled" in data
    assert "waf_block_min_severity" in data
    assert "body_preview_max" in data
    assert "upstream_ok" in data
