"""FastAPI 앱 헬스 엔드포인트 (업스트림 연결 없음)."""

from __future__ import annotations

from starlette.testclient import TestClient

from main import app


def test_proxy_health_ok() -> None:
    client = TestClient(app)
    r = client.get("/__proxy/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "upstream" in data
    assert "waf_enabled" in data
    assert "waf_block_min_severity" in data
    assert data.get("dashboard_path") == "/__waf/dashboard"
    assert "process_started_at" in data
    assert len(str(data.get("process_started_at") or "")) >= 10
