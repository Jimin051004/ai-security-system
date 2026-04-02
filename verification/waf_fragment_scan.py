"""location.hash 대응: POST /__waf/api/scan-fragment 로 SSTI 등 탐지."""

from __future__ import annotations

from starlette.testclient import TestClient

from main import app


def test_scan_fragment_ssti_in_hash_string() -> None:
    client = TestClient(app)
    r = client.post(
        "/__waf/api/scan-fragment",
        json={"fragment": "#/{{7*7}}"},
    )
    assert r.status_code == 403
    data = r.json()
    assert data.get("blocked") is True
    assert any(f.get("rule_id") == "A05-SSTI-001" for f in data.get("findings", []))


def test_scan_fragment_empty_ok() -> None:
    client = TestClient(app)
    r = client.post("/__waf/api/scan-fragment", json={"fragment": ""})
    assert r.status_code == 200
    assert r.json().get("status") == "ok"


def test_scan_fragment_whitespace_only_ok() -> None:
    client = TestClient(app)
    r = client.post("/__waf/api/scan-fragment", json={"fragment": "  \n"})
    assert r.status_code == 200
