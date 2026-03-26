"""프록시 트래픽 로그 API·기록."""

from __future__ import annotations

import asyncio

from starlette.requests import Request
from starlette.testclient import TestClient

import traffic_log
from main import app


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
    client = TestClient(app)
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
    assert rows[1].get("block_findings") in ([], ())


def test_waf_paths_not_logged() -> None:
    traffic_log.clear()
    client = TestClient(app)
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


def test_clients_api_json() -> None:
    traffic_log.clear()
    client = TestClient(app)
    r = client.get("/__waf/api/clients")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["unique_clients"] == 0
    assert data["clients"] == []
