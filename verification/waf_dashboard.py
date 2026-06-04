"""중앙 대시보드(dashboard_app) 페이지·API와 프록시(main) 로그 연동 검증."""

from __future__ import annotations

import asyncio
import io
import zipfile
from urllib.parse import quote

from starlette.testclient import TestClient

import auth
import traffic_log
from dashboard_app import app as dashboard_app
from main import app as proxy_app


def _login_dashboard(client: TestClient) -> None:
    r = client.post(
        "/login",
        data={"username": "admin", "password": "admin"},
        follow_redirects=True,
    )
    assert r.status_code == 200, r.text


def test_dashboard_canonical_renders_overview_when_authenticated() -> None:
    with TestClient(dashboard_app) as client:
        r0 = client.get("/__waf/dashboard", follow_redirects=False)
        assert r0.status_code == 302
        assert r0.headers.get("location") == "/login"

        _login_dashboard(client)
        r = client.get("/__waf/dashboard")
        assert r.status_code == 200
        assert 'data-waf-page="overview"' in r.text
        assert "차단 KPI" in r.text
        assert "pipeline-hint-banner" in r.text
        assert "CENTRAL_DASHBOARD_URL" in r.text


def test_dashboard_traffic_page_200() -> None:
    with TestClient(dashboard_app) as client:
        _login_dashboard(client)
        r = client.get("/__waf/dashboard/traffic")
        assert r.status_code == 200
        assert "/__waf/static/css/dashboard.css" in r.text
        assert "/__waf/static/js/dashboard.js" in r.text
        assert "/__waf/dashboard/detections" in r.text
        assert "/__waf/dashboard/settings" in r.text
        assert "프록시 로그" in r.text
        assert "filter-method" in r.text
        assert 'data-waf-page="traffic"' in r.text
        assert "no-store" in r.headers.get("cache-control", "").lower()


def test_dashboard_overview_section_200() -> None:
    with TestClient(dashboard_app) as client:
        _login_dashboard(client)
        r = client.get("/__waf/dashboard/overview")
        assert r.status_code == 200
        assert "차단 KPI" in r.text
        assert 'data-waf-page="overview"' in r.text
        assert "proxy-public-origin" in r.text


def test_dashboard_preview_route_200() -> None:
    with TestClient(dashboard_app) as client:
        _login_dashboard(client)
        r = client.get("/__waf/dashboard-preview")
        assert r.status_code == 200
        assert 'data-waf-page="preview"' in r.text
        assert "보안 운영자가 바로 판단할 수 있는 화면" in r.text
        assert "AI Second Pass" in r.text
        assert "preview-kpi-strip" in r.text


def test_dashboard_detections_page_200() -> None:
    with TestClient(dashboard_app) as client:
        _login_dashboard(client)
        r = client.get("/__waf/dashboard/detections")
        assert r.status_code == 200
        assert "detections-feed-body" in r.text
        assert 'data-waf-page="detections"' in r.text
        assert "detections-route-hint" in r.text


def test_dashboard_sql_page_200() -> None:
    with TestClient(dashboard_app) as client:
        _login_dashboard(client)
        r = client.get("/__waf/dashboard/sql")
        assert r.status_code == 200
        assert 'data-waf-page="sql"' in r.text
        assert "sql-editor" in r.text
        assert "/__waf/dashboard/sql" in r.text


def test_proxy_worker_env_download_regular_user() -> None:
    auth.ensure_default_users()
    with TestClient(dashboard_app) as client:
        r_login = client.post(
            "/login",
            data={"username": "jimin", "password": "jimin"},
            follow_redirects=True,
        )
        assert r_login.status_code == 200, r_login.text
        r = client.get("/__waf/api/me/proxy-worker-env")
        assert r.status_code == 200, r.text
        txt = r.text
        assert "CENTRAL_DASHBOARD_URL=http://testserver" in txt
        assert "SITE_ID=juiceshop" in txt
        assert "SENSOR_TOKEN=sensor_" in txt
        assert "UPSTREAM_URL=http://127.0.0.1:3000" in txt


def test_proxy_worker_env_custom_upstream_query() -> None:
    auth.ensure_default_users()
    with TestClient(dashboard_app) as client:
        client.post(
            "/login",
            data={"username": "jimin", "password": "jimin"},
            follow_redirects=True,
        )
        r = client.get(
            "/__waf/api/me/proxy-worker-env?upstream="
            + "http%3A%2F%2F192.168.100.151%3A3000"
        )
        assert r.status_code == 200
        assert "UPSTREAM_URL=http://192.168.100.151:3000" in r.text


def test_proxy_worker_env_upstream_hash_stripped_in_query() -> None:
    """브라우저 SPA 주소의 #fragment는 UPSTREAM 에 넣지 않음."""
    auth.ensure_default_users()
    with TestClient(dashboard_app) as client:
        client.post(
            "/login",
            data={"username": "jimin", "password": "jimin"},
            follow_redirects=True,
        )
        frag = quote("http://192.168.100.151:3000/#/", safe="")
        r = client.get("/__waf/api/me/proxy-worker-env?upstream=" + frag)
        assert r.status_code == 200
        assert "UPSTREAM_URL=http://192.168.100.151:3000" in r.text
        for line in r.text.splitlines():
            if line.startswith("UPSTREAM_URL="):
                assert "#" not in line
                assert line == "UPSTREAM_URL=http://192.168.100.151:3000"
                break
        else:
            raise AssertionError("UPSTREAM_URL line missing")


def test_normalize_upstream_base_url_strips_fragment() -> None:
    assert (
        traffic_log.normalize_upstream_base_url("http://192.168.100.151:3000/#/")
        == "http://192.168.100.151:3000"
    )
    assert (
        traffic_log.normalize_upstream_base_url("http://host:3000/api/foo///")
        == "http://host:3000/api/foo"
    )


def test_put_public_url_hint_normalizes_fragment() -> None:
    auth.ensure_default_users()
    with TestClient(dashboard_app) as client:
        client.post(
            "/login",
            data={"username": "jimin", "password": "jimin"},
            follow_redirects=True,
        )
        r = client.put(
            "/__waf/api/me/public-url-hint",
            json={"public_url": "http://192.168.100.151:3000/#/"},
        )
        assert r.status_code == 200
        assert r.json().get("public_url") == "http://192.168.100.151:3000"


def test_proxy_worker_env_rejects_admin() -> None:
    auth.ensure_default_users()
    with TestClient(dashboard_app) as client:
        _login_dashboard(client)
        r = client.get("/__waf/api/me/proxy-worker-env")
        assert r.status_code == 400


def test_worker_connect_zip_regular_user() -> None:
    auth.ensure_default_users()
    with TestClient(dashboard_app) as client:
        client.post(
            "/login",
            data={"username": "jimin", "password": "jimin"},
            follow_redirects=True,
        )
        r = client.get("/__waf/api/me/worker-connect-zip")
        assert r.status_code == 200, r.text
        assert "zip" in r.headers.get("content-type", "").lower()
        zf = zipfile.ZipFile(io.BytesIO(r.content))
        names = zf.namelist()
        assert "waf-worker.env" in names
        assert "연결안내.txt" in names
        inner = zf.read("waf-worker.env").decode("utf-8")
        assert "CENTRAL_DASHBOARD_URL=http://testserver" in inner
        assert "SITE_ID=juiceshop" in inner
        readme = zf.read("연결안내.txt").decode("utf-8")
        assert "UPSTREAM_URL" in readme or "워커" in readme or "프록시" in readme


def test_worker_connect_zip_custom_upstream_query() -> None:
    auth.ensure_default_users()
    with TestClient(dashboard_app) as client:
        client.post(
            "/login",
            data={"username": "jimin", "password": "jimin"},
            follow_redirects=True,
        )
        r = client.get(
            "/__waf/api/me/worker-connect-zip?upstream="
            + "http%3A%2F%2F192.168.100.151%3A3000"
        )
        assert r.status_code == 200
        zf = zipfile.ZipFile(io.BytesIO(r.content))
        inner = zf.read("waf-worker.env").decode("utf-8")
        assert "UPSTREAM_URL=http://192.168.100.151:3000" in inner


def test_worker_connect_zip_rejects_admin() -> None:
    auth.ensure_default_users()
    with TestClient(dashboard_app) as client:
        _login_dashboard(client)
        r = client.get("/__waf/api/me/worker-connect-zip")
        assert r.status_code == 400


def test_sql_console_schema_api() -> None:
    with TestClient(dashboard_app) as client:
        _login_dashboard(client)
        r = client.get("/__waf/api/sql-console/schema")
        assert r.status_code == 200
        d = r.json()
        assert d.get("status") == "ok"
        assert "db_path_resolved" in d
        assert "db_display_name" in d
        assert isinstance(d.get("tables"), list)


def test_sql_console_query_select_ok() -> None:
    with TestClient(dashboard_app) as client:
        _login_dashboard(client)
        r = client.post(
            "/__waf/api/sql-console/query", json={"sql": "SELECT 2 AS n, 'x' AS t"}
        )
        assert r.status_code == 200
        d = r.json()
        assert d.get("status") == "ok"
        assert d.get("columns") == ["n", "t"]
        assert d.get("rows") == [[2, "x"]]


def test_sql_console_write_rejected() -> None:
    with TestClient(dashboard_app) as client:
        _login_dashboard(client)
        r = client.post(
            "/__waf/api/sql-console/query",
            json={"sql": "INSERT INTO traffic_events (id) VALUES (1)"},
        )
        assert r.status_code == 400


def test_dashboard_settings_page_200() -> None:
    with TestClient(dashboard_app) as client:
        _login_dashboard(client)
        r = client.get("/__waf/dashboard/settings")
        assert r.status_code == 200
        assert "form-traffic-store" in r.text
        assert "input-traffic-log-db" in r.text
        assert "btn-apply-db-path" in r.text
        assert "전체 로그 초기화" in r.text
        assert 'data-waf-page="settings"' in r.text


def test_dashboard_static_css_js_200() -> None:
    with TestClient(dashboard_app) as client:
        _login_dashboard(client)
        css = client.get("/__waf/static/css/dashboard.css")
        assert css.status_code == 200
        assert "text/css" in css.headers.get("content-type", "")
        assert b":root" in css.content
        js = client.get("/__waf/static/js/dashboard.js")
        assert js.status_code == 200
        assert b"pageBoot" in js.content


def test_proxy_waf_unknown_path_json_404() -> None:
    with TestClient(proxy_app) as client:
        r = client.get("/__waf/scripts.js")
        assert r.status_code == 404
        assert r.headers.get("content-type", "").startswith("application/json")
        assert "detail" in r.json()


def test_dashboard_legacy_redirects() -> None:
    with TestClient(dashboard_app, follow_redirects=False) as client:
        for path in ("/dashboard", "/dashboard/"):
            r = client.get(path)
            assert r.status_code == 302
            assert r.headers.get("location") == "/login"

        _login_dashboard(client)
        for path in ("/dashboard", "/dashboard/"):
            r = client.get(path)
            assert r.status_code == 307
            assert r.headers.get("location") == "/__waf/dashboard"


def test_api_dashboard_summary_json() -> None:
    with TestClient(dashboard_app) as client:
        _login_dashboard(client)
        r = client.get("/__waf/api/summary")
        assert r.status_code == 200
        data = r.json()
        assert data.get("status") == "ok"
        assert data.get("summary_scope") == "central"
        assert "sites" in data
        assert "waf_enabled" in data
        assert "waf_block_min_severity" in data
        assert "body_preview_max" in data
        assert "upstream_ok" in data
        assert "process_started_at" in data
        assert "proxy_public_origin" in data
        assert "env" in data
        assert "TRAFFIC_LOG_DB" in data["env"]
        ts = data.get("traffic_store")
        assert isinstance(ts, dict)
        assert "traffic_log_db_resolved" in ts
        assert "stored_row_count" in ts
        ds = data.get("dashboard_stats")
        assert isinstance(ds, dict)
        assert "total_logged" in ds
        assert ds.get("total_logged") == data.get("traffic_total_logged")
        assert isinstance(data.get("site_cards"), list)


def test_api_dashboard_summary_legacy_path() -> None:
    with TestClient(dashboard_app) as client:
        _login_dashboard(client)
        r = client.get("/api/dashboard/summary")
        assert r.status_code == 200
        assert r.json().get("status") == "ok"
        assert "proxy_public_origin" in r.json()


def test_waf_api_modules_lists_a05() -> None:
    with TestClient(dashboard_app) as client:
        _login_dashboard(client)
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
        assert a01.get("implementation") == "rules"


def test_waf_api_stats_json() -> None:
    with TestClient(dashboard_app) as client:
        _login_dashboard(client)
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
    with TestClient(proxy_app) as pc:
        r = pc.get(
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

    with TestClient(dashboard_app) as dc:
        _login_dashboard(dc)
        tr = dc.get("/__waf/api/traffic")
        assert tr.status_code == 200
        events = tr.json().get("events") or []
        assert len(events) >= 1
        top = events[0]
        assert top.get("blocked") is True
        bf = top.get("block_findings") or []
        assert len(bf) >= 1
        assert bf[0].get("rule_id", "").startswith("A05-SQL")
        assert bf[0].get("location") not in (None, "")


def test_sensor_site_waf_reads_central_toggle() -> None:
    auth.ensure_default_users()
    asyncio.run(traffic_log.set_site_waf_enabled("lab-demo-waf-toggle", False))
    cfg = auth.get_sensor_config_for_username("admin") or {}
    sensor = str(cfg.get("sensor_token") or "")
    assert sensor
    with TestClient(dashboard_app) as client:
        r = client.get(
            "/__waf/api/sensor/site-waf",
            params={"site": "lab-demo-waf-toggle"},
            headers={"X-Sensor-Token": sensor},
        )
        assert r.status_code == 200
        data = r.json()
        assert data.get("site_id") == "lab-demo-waf-toggle"
        assert data.get("waf_enabled") is False


def test_dashboard_post_site_waf_enabled() -> None:
    asyncio.run(traffic_log.set_site_waf_enabled("lab-demo-waf-toggle-b", True))
    with TestClient(dashboard_app) as client:
        _login_dashboard(client)
        r = client.post(
            "/__waf/api/settings/waf-enabled",
            json={"enabled": False, "site_id": "lab-demo-waf-toggle-b"},
        )
        assert r.status_code == 200
        assert r.json().get("waf_enabled") is False
        r2 = client.get(
            "/__waf/api/summary",
            params={"site": "lab-demo-waf-toggle-b"},
        )
        assert r2.status_code == 200
        assert r2.json().get("waf_enabled") is False
