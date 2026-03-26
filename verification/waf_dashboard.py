"""웹 대시보드·요약 API."""

from __future__ import annotations

from starlette.testclient import TestClient

import traffic_log
from main import app


def test_dashboard_canonical_200() -> None:
    client = TestClient(app)
    r = client.get("/__waf/dashboard")
    assert r.status_code == 200
    assert "대시보드" in r.text
    assert "업스트림" in r.text
    assert "/__waf/static/css/dashboard.css" in r.text
    assert "/__waf/static/js/dashboard.js" in r.text
    assert "접속자" in r.text
    assert "프록시 로그" in r.text
    assert "detections-feed-body" in r.text
    assert "탐지·차단 상세" in r.text
    assert "차단 KPI" in r.text
    assert "waf-severity-group" in r.text
    assert "proxy-public-origin" in r.text
    assert "env-snapshot" in r.text
    assert "자동 갱신" in r.text
    assert "no-store" in r.headers.get("cache-control", "")


def test_dashboard_static_css_js_200() -> None:
    client = TestClient(app)
    css = client.get("/__waf/static/css/dashboard.css")
    assert css.status_code == 200
    assert "text/css" in css.headers.get("content-type", "")
    assert b":root" in css.content
    js = client.get("/__waf/static/js/dashboard.js")
    assert js.status_code == 200
    assert b"loadSummary" in js.content


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
    assert "process_started_at" in data
    assert "proxy_public_origin" in data
    assert "env" in data
    assert "UPSTREAM_URL" in data["env"]


def test_api_dashboard_summary_legacy_path() -> None:
    client = TestClient(app)
    r = client.get("/api/dashboard/summary")
    assert r.status_code == 200
    assert "upstream" in r.json()


def test_waf_api_modules_lists_a05() -> None:
    client = TestClient(app)
    r = client.get("/__waf/api/modules")
    assert r.status_code == 200
    data = r.json()
    assert data.get("status") == "ok"
    ids = [m["module_id"] for m in data.get("modules", [])]
    assert "a05" in ids
    a05 = next(m for m in data["modules"] if m["module_id"] == "a05")
    assert a05.get("title") == "Injection"
    assert a05.get("implementation") == "rules"
    a01 = next(m for m in data["modules"] if m["module_id"] == "a01")
    assert a01.get("implementation") == "skeleton"


def test_waf_api_set_block_severity() -> None:
    import os

    client = TestClient(app)
    old = os.environ.get("WAF_BLOCK_MIN_SEVERITY")
    try:
        r = client.put(
            "/__waf/api/settings/block-severity",
            json={"min_severity": "critical"},
        )
        assert r.status_code == 200
        assert r.json().get("waf_block_min_severity") == "critical"
        summ = client.get("/__waf/api/summary").json()
        assert summ.get("waf_block_min_severity") == "critical"
        assert summ["env"]["WAF_BLOCK_MIN_SEVERITY"] == "critical"
        bad = client.put(
            "/__waf/api/settings/block-severity",
            json={"min_severity": "nope"},
        )
        assert bad.status_code == 400
    finally:
        if old is not None:
            os.environ["WAF_BLOCK_MIN_SEVERITY"] = old
        else:
            os.environ.pop("WAF_BLOCK_MIN_SEVERITY", None)


def test_waf_api_stats_json() -> None:
    client = TestClient(app)
    r = client.get("/__waf/api/stats")
    assert r.status_code == 200
    d = r.json()
    assert d.get("status") == "ok"
    assert "total_logged" in d
    assert "blocked_count" in d
    assert "block_ratio" in d
    assert "top_attack_types" in d
    assert "top_rule_ids" in d


def test_blocked_request_logs_enriched_findings_in_traffic_api() -> None:
    traffic_log.clear()
    client = TestClient(app)
    r = client.get(
        "/api/x?q=test' OR '1'='1",
        headers={"Accept": "application/json"},
    )
    assert r.status_code == 403
    data = r.json()
    assert data.get("blocked") is True
    findings = data.get("findings") or []
    assert len(findings) >= 1
    assert findings[0].get("owasp_id") == "A05:2025"
    assert findings[0].get("category") == "Injection"
    assert "SQL" in (findings[0].get("attack_type") or "")
    tr = client.get("/__waf/api/traffic")
    events = tr.json().get("events") or []
    assert len(events) >= 1
    top = events[0]
    assert top.get("blocked") is True
    bf = top.get("block_findings") or []
    assert len(bf) >= 1
    assert bf[0].get("rule_id", "").startswith("A05-SQL")
    assert bf[0].get("location") not in (None, "")
