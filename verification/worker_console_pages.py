"""프록시 워커 전용 /__waf/worker/* 로컬 로그 콘솔."""

from __future__ import annotations

import traffic_log
from starlette.testclient import TestClient

from main import app


def test_worker_logs_redirects_to_login_without_session() -> None:
    client = TestClient(app)
    r = client.get("/__waf/worker/logs", follow_redirects=False)
    assert r.status_code == 302
    assert "/__waf/worker/login" in (r.headers.get("location") or "")


def test_worker_api_traffic_requires_admin_session() -> None:
    client = TestClient(app)
    r = client.get("/__waf/worker/api/traffic")
    assert r.status_code == 401


def test_worker_api_ai_status_requires_admin_session() -> None:
    client = TestClient(app)
    r = client.get("/__waf/worker/api/ai-status")
    assert r.status_code == 401


def test_worker_admin_sees_ai_status() -> None:
    client = TestClient(app)
    assert client.post(
        "/__waf/worker/login",
        data={"username": "admin", "password": "admin"},
    ).status_code in (302, 303, 200)
    r = client.get("/__waf/worker/api/ai-status")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "ai_second_pass" in data
    assert "enabled" in data["ai_second_pass"]


def test_worker_admin_sees_blocked_request_in_local_traffic_api() -> None:
    traffic_log.clear()
    client = TestClient(app)
    assert client.post(
        "/__waf/worker/login",
        data={"username": "admin", "password": "admin"},
    ).status_code in (302, 303, 200)
    blk = client.get(
        "/api/x?q=test' OR '1'='1",
        headers={"Accept": "application/json"},
    )
    assert blk.status_code == 403
    tr = client.get("/__waf/worker/api/traffic")
    assert tr.status_code == 200
    events = tr.json().get("events") or []
    assert len(events) >= 1
    assert events[0].get("blocked") is True
