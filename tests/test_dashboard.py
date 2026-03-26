"""웹 대시보드·요약 API."""

from __future__ import annotations

from starlette.testclient import TestClient

from main import app


def test_dashboard_canonical_200() -> None:
    client = TestClient(app)
    r = client.get("/__waf/dashboard")
    assert r.status_code == 200
    assert "AI Security System" in r.text
    assert "업스트림" in r.text
    assert "no-store" in r.headers.get("cache-control", "")


def test_waf_unknown_path_json_404() -> None:
    client = TestClient(app)
    r = client.get("/__waf/scripts.js")
    assert r.status_code == 404
    assert r.headers.get("content-type", "").startswith("application/json")
    assert "detail" in r.json()


def test_dashboard_legacy_redirects() -> None:
    client = TestClient(app, follow_redirects=False)
    for path in ("/dashboard", "/dashboard/"):
        r = client.get(path)
        assert r.status_code == 307
        assert r.headers.get("location") == "/__waf/dashboard"


def test_api_dashboard_summary_json() -> None:
    client = TestClient(app)
    r = client.get("/__waf/api/summary")
    assert r.status_code == 200
    data = r.json()
    assert "upstream" in data
    assert "waf_enabled" in data
    assert "waf_block_min_severity" in data
    assert "body_preview_max" in data
    assert "upstream_ok" in data
    assert "access" in data
    assert "client_ip" in data["access"]
    assert "user_agent" in data["access"]


def test_api_dashboard_summary_legacy_path() -> None:
    client = TestClient(app)
    r = client.get("/api/dashboard/summary")
    assert r.status_code == 200
    assert "upstream" in r.json()
