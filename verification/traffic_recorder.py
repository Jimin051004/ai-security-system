"""프록시 트래픽 로그 API·기록.

트래픽 REST API(`/__waf/api/traffic` 등)는 중앙 dashboard_app 에만 있으며, 프록시 main 은 라우팅하지 않습니다.
직접 traffic_log 호출 테스트는 저장소 모듈만 사용합니다."""

from __future__ import annotations

import asyncio

from starlette.requests import Request
from starlette.testclient import TestClient

import traffic_log
from dashboard_app import app as dashboard_app


def _dash_login(client: TestClient) -> None:
    r = client.post(
        "/login",
        data={"username": "admin", "password": "admin"},
        follow_redirects=True,
    )
    assert r.status_code == 200


def _fake_request(path: str) -> Request:
    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [
                (b"host", b"127.0.0.1:8080"),
                (b"user-agent", b"pytest-client/1"),
            ],
            "client": ("203.0.113.9", 5555),
            "server": ("127.0.0.1", 8080),
        }
    )


def test_traffic_api_returns_events_list() -> None:
    traffic_log.clear()
    with TestClient(dashboard_app) as client:
        _dash_login(client)
        r = client.get("/__waf/api/traffic")
        assert r.status_code == 200
        data = r.json()
        assert data.get("status") == "ok"
        assert data.get("events") == []


def test_traffic_record_and_snapshot_order() -> None:
    traffic_log.clear()
    req = _fake_request("/checkout")

    async def run() -> None:
        await traffic_log.record(req, status_code=200, blocked=False)
        await traffic_log.record(_fake_request("/api/x"), status_code=502, blocked=False)

    asyncio.run(run())
    rows = asyncio.run(traffic_log.snapshot_dicts())
    assert len(rows) == 2
    assert rows[0]["path"] == "/api/x"
    assert rows[0]["status_code"] == 502
    assert rows[1]["path"] == "/checkout"
    assert rows[1]["client_ip"] == "203.0.113.9"
    assert rows[1]["blocked"] is False
    assert rows[1].get("block_findings") == []


def test_waf_paths_not_logged() -> None:
    traffic_log.clear()
    with TestClient(dashboard_app) as client:
        _dash_login(client)
        client.get("/__waf/api/summary")
        r = client.get("/__waf/api/traffic")
        assert r.json()["events"] == []


def test_clients_aggregation_same_ip() -> None:
    traffic_log.clear()

    async def run() -> None:
        await traffic_log.record(_fake_request("/a"), status_code=200, blocked=False)
        await traffic_log.record(_fake_request("/b"), status_code=200, blocked=False)

    asyncio.run(run())
    snap = asyncio.run(traffic_log.clients_snapshot())
    assert snap["unique_clients"] == 1
    assert snap["clients"][0]["requests"] == 2
    assert snap["clients"][0]["client_ip"] == "203.0.113.9"


def test_stats_snapshot_empty_buffer() -> None:
    traffic_log.clear()
    snap = asyncio.run(traffic_log.stats_snapshot())
    assert snap["status"] == "ok"
    assert snap["total_logged"] == 0
    assert snap["blocked_count"] == 0
    assert snap["block_ratio"] == 0.0
    assert snap["top_attack_types"] == []
    assert snap["top_rule_ids"] == []


def test_clients_api_json() -> None:
    traffic_log.clear()
    with TestClient(dashboard_app) as client:
        _dash_login(client)
        r = client.get("/__waf/api/clients")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["unique_clients"] == 0
        assert data["clients"] == []


def test_traffic_delete_one() -> None:
    traffic_log.clear()
    with TestClient(dashboard_app) as client:
        _dash_login(client)
        asyncio.run(traffic_log.record(_fake_request("/z"), status_code=200, blocked=False))
        eid = client.get("/__waf/api/traffic").json()["events"][0]["id"]
        assert client.delete(f"/__waf/api/traffic/{eid}").status_code == 200
        assert client.get("/__waf/api/traffic").json()["events"] == []
        assert client.delete("/__waf/api/traffic/999999").status_code == 404


def test_traffic_reset_all() -> None:
    traffic_log.clear()
    with TestClient(dashboard_app) as client:
        _dash_login(client)
        asyncio.run(traffic_log.record(_fake_request("/a"), status_code=200, blocked=False))
        assert client.post("/__waf/api/traffic/reset").json().get("cleared") is True
        assert client.get("/__waf/api/traffic").json()["events"] == []


def test_traffic_store_settings_api() -> None:
    import os

    traffic_log.clear()
    old_snap = os.environ.get("TRAFFIC_LOG_SNAPSHOT_LIMIT")
    old_max = os.environ.get("TRAFFIC_LOG_MAX_ROWS")
    try:
        with TestClient(dashboard_app) as client:
            _dash_login(client)
            g = client.get("/__waf/api/settings/traffic-store")
            assert g.status_code == 200
            assert "snapshot_limit" in g.json()
            r = client.put(
                "/__waf/api/settings/traffic-store",
                json={"snapshot_limit": 120, "max_stored_rows": 0},
            )
            assert r.status_code == 200
            assert r.json().get("snapshot_limit") == 120
    finally:
        if old_snap is not None:
            os.environ["TRAFFIC_LOG_SNAPSHOT_LIMIT"] = old_snap
        else:
            os.environ.pop("TRAFFIC_LOG_SNAPSHOT_LIMIT", None)
        if old_max is not None:
            os.environ["TRAFFIC_LOG_MAX_ROWS"] = old_max
        else:
            os.environ.pop("TRAFFIC_LOG_MAX_ROWS", None)


def test_traffic_store_reopen_db_path(tmp_path) -> None:
    traffic_log.clear()
    p1 = tmp_path / "one.sqlite3"
    p2 = tmp_path / "two.sqlite3"
    try:
        with TestClient(dashboard_app) as client:
            _dash_login(client)
            assert (
                client.put(
                    "/__waf/api/settings/traffic-store",
                    json={"traffic_log_db": str(p1)},
                ).status_code
                == 200
            )
        asyncio.run(
            traffic_log.record(_fake_request("/in-p1"), status_code=200, blocked=False)
        )
        with TestClient(dashboard_app) as client:
            _dash_login(client)
            assert len(client.get("/__waf/api/traffic").json()["events"]) == 1
            assert (
                client.put(
                    "/__waf/api/settings/traffic-store",
                    json={"traffic_log_db": str(p2)},
                ).status_code
                == 200
            )
            assert client.get("/__waf/api/traffic").json()["events"] == []
    finally:
        asyncio.run(traffic_log.reopen_database_async(":memory:"))


def test_traffic_store_invalid_db_path_400() -> None:
    with TestClient(dashboard_app) as client:
        _dash_login(client)
        r = client.put(
            "/__waf/api/settings/traffic-store",
            json={"traffic_log_db": "bad\x00.sqlite"},
        )
    assert r.status_code == 400
