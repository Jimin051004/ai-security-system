"""중앙 대시보드 ingest: 관리자 sensor_token 허용(과거 버그: admin 토큰 시 항상 403)."""

from __future__ import annotations

import auth
import traffic_log
from starlette.testclient import TestClient

from dashboard_app import app as dashboard_app


def test_admin_sensor_token_allows_ingest_for_proxy_site_label() -> None:
    traffic_log.clear()
    auth.ensure_default_users()
    cfg = auth.get_sensor_config_for_username("admin")
    assert cfg is not None and cfg["sensor_token"]
    token = cfg["sensor_token"]

    with TestClient(dashboard_app) as client:
        r = client.post(
            "/__waf/api/ingest",
            json={
                "site_id": "juiceshop",
                "sensor_token": token,
                "method": "GET",
                "path": "/ingest-marker-test",
                "status_code": 200,
                "blocked": False,
            },
            headers={"X-Sensor-Token": token},
        )
        assert r.status_code == 200, r.text
        assert r.json().get("site_id")

        login = client.post(
            "/login", data={"username": "admin", "password": "admin"}
        )
        assert login.status_code in (200, 302, 303)

        tr = client.get("/__waf/api/traffic")
        assert tr.status_code == 200
        paths = [e.get("path") for e in (tr.json().get("events") or [])]
        assert "/ingest-marker-test" in paths


def test_ingest_sensor_label_registers_site_cards() -> None:
    """프록시가 ingest 시 보내는 표시 이름·프록시 URL 이 사이트 필터 목록에 반영된다."""
    traffic_log.clear()
    auth.ensure_default_users()
    cfg = auth.get_sensor_config_for_username("admin")
    assert cfg is not None and cfg["sensor_token"]
    token = cfg["sensor_token"]

    with TestClient(dashboard_app) as client:
        ingest = client.post(
            "/__waf/api/ingest",
            json={
                "site_id": "juiceshop",
                "sensor_token": token,
                "sensor_label": "Juice shop1",
                "sensor_public_origin": "http://192.168.100.155:8081",
                "method": "GET",
                "path": "/site-card-marker",
                "status_code": 200,
                "blocked": False,
            },
            headers={"X-Sensor-Token": token},
        )
        assert ingest.status_code == 200, ingest.text

        client.post(
            "/login",
            data={"username": "admin", "password": "admin"},
            follow_redirects=True,
        )
        r = client.get("/__waf/api/sites")
        assert r.status_code == 200
        data = r.json()
        cards = data.get("site_cards") or []
        assert isinstance(cards, list) and len(cards) >= 1
        js = next(c for c in cards if c.get("site_id") == "juiceshop")
        assert js.get("label") == "Juice shop1"
        assert js.get("public_url") == "http://192.168.100.155:8081"
        assert "juiceshop" in (data.get("sites") or [])


def test_tenant_sensor_token_must_match_site_id() -> None:
    """일반 사용자(jimin→juiceshop) 토큰은 해당 site_id 와 같을 때만 통과."""
    traffic_log.clear()
    auth.ensure_default_users()
    cfg = auth.get_sensor_config_for_username("jimin")
    assert cfg is not None and cfg["sensor_token"]
    token = cfg["sensor_token"]

    with TestClient(dashboard_app) as client:
        bad = client.post(
            "/__waf/api/ingest",
            json={
                "site_id": "wrong-site-xx",
                "sensor_token": token,
                "method": "GET",
                "path": "/bad",
                "status_code": 200,
                "blocked": False,
            },
            headers={"X-Sensor-Token": token},
        )
        assert bad.status_code == 403

        ok = client.post(
            "/__waf/api/ingest",
            json={
                "site_id": "juiceshop",
                "sensor_token": token,
                "method": "GET",
                "path": "/ok-tenant-ingest",
                "status_code": 200,
                "blocked": False,
            },
            headers={"X-Sensor-Token": token},
        )
        assert ok.status_code == 200, ok.text
