"""AI 2차 탐지/차단 검증."""

from __future__ import annotations

import asyncio

import ai_second_pass
import main
import traffic_log
from ai_second_pass import AISecondPassVerdict, verdict_to_finding
from owasp.types import RequestContext, Severity
from starlette.testclient import TestClient


def test_ai_second_pass_only_runs_for_suspicious_requests(monkeypatch) -> None:
    monkeypatch.setenv("AI_SECOND_PASS_ENABLED", "true")
    ctx_normal = RequestContext(
        method="GET",
        path="/",
        query_string="",
        headers={},
        body_preview="",
    )
    ctx_suspicious = RequestContext(
        method="GET",
        path="/search",
        query_string="q=' OR 1=1--",
        headers={},
        body_preview="",
    )
    assert ai_second_pass.should_run_ai_second_pass(ctx_normal, []) is False
    assert ai_second_pass.should_run_ai_second_pass(ctx_suspicious, []) is True


def test_ai_verdict_to_finding_uses_existing_finding_shape() -> None:
    verdict = AISecondPassVerdict(
        malicious=True,
        confidence=0.91,
        attack_type="SQL Injection",
        severity=Severity.HIGH,
        reason="tautology payload",
        recommended_action="block",
        raw={},
    )
    finding = verdict_to_finding(verdict)
    assert finding.rule_id == "AI-SECOND-PASS"
    assert finding.severity == Severity.HIGH
    assert "confidence=0.91" in finding.evidence
    assert finding.location == "ai.second_pass"


def test_ai_gate_blocks_when_second_pass_confident(monkeypatch) -> None:
    async def fake_judge(_ctx, _findings):
        return AISecondPassVerdict(
            malicious=True,
            confidence=0.88,
            attack_type="Suspicious Redirect",
            severity=Severity.HIGH,
            reason="external redirect parameter",
            recommended_action="block",
            raw={},
        )

    traffic_log.clear()
    monkeypatch.setattr(main, "judge_request_with_ai", fake_judge)
    monkeypatch.setattr(main, "ai_block_min_confidence", lambda: 0.75)
    client = TestClient(main.app)
    resp = client.get(
        "/safe-ai-check?next=https://evil.example",
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data["blocked"] is True
    assert data["findings"][0]["rule_id"] == "AI-SECOND-PASS"


def test_ai_judge_parses_ollama_json(monkeypatch) -> None:
    class FakeResponse:
        status_code = 200

        def json(self):
            return {
                "response": (
                    '{"malicious":true,"confidence":0.82,"attack_type":"XSS",'
                    '"severity":"high","reason":"script tag","recommended_action":"block"}'
                )
            }

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *args, **kwargs):
            return FakeResponse()

    monkeypatch.setenv("AI_SECOND_PASS_ENABLED", "true")
    monkeypatch.setattr(ai_second_pass.httpx, "AsyncClient", FakeAsyncClient)
    ctx = RequestContext(
        method="GET",
        path="/search",
        query_string="q=<script>alert(1)</script>",
        headers={"cookie": "sid=secret", "user-agent": "pytest"},
        body_preview='{"password":"secret"}',
    )
    verdict = asyncio.run(ai_second_pass.judge_request_with_ai(ctx, []))
    assert verdict is not None
    assert verdict.should_block is True
    assert verdict.confidence == 0.82
    assert verdict.attack_type == "XSS"
    status = ai_second_pass.ai_second_pass_status()
    assert status["last_ok"] is True
    assert status["last_decision"] == "block_candidate"


def test_ai_payload_redacts_sensitive_values(monkeypatch) -> None:
    monkeypatch.setenv("AI_SECOND_PASS_BODY_MAX_CHARS", "400")
    ctx = RequestContext(
        method="POST",
        path="/login",
        query_string="token=super-secret-token&q=test",
        headers={
            "authorization": "Bearer secret",
            "cookie": "sid=secret",
            "user-agent": "pytest",
        },
        body_preview='{"password":"secret-pass","api_key":"secret-key","name":"jimin"}',
    )
    payload = ai_second_pass._payload_for_model(ctx, [])
    raw = str(payload)
    assert "Bearer secret" not in raw
    assert "sid=secret" not in raw
    assert "secret-pass" not in raw
    assert "secret-key" not in raw
    assert "[REDACTED]" in raw


def test_ai_judge_timeout_falls_back_and_records_status(monkeypatch) -> None:
    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *args, **kwargs):
            raise ai_second_pass.httpx.TimeoutException("timeout")

    monkeypatch.setenv("AI_SECOND_PASS_ENABLED", "true")
    monkeypatch.setattr(ai_second_pass.httpx, "AsyncClient", FakeAsyncClient)
    ctx = RequestContext(
        method="GET",
        path="/search",
        query_string="next=https://evil.example",
        headers={},
        body_preview="",
    )
    verdict = asyncio.run(ai_second_pass.judge_request_with_ai(ctx, []))
    assert verdict is None
    status = ai_second_pass.ai_second_pass_status()
    assert status["last_ok"] is False
    assert status["last_error_type"] == "timeout"
    assert status["last_decision"] == "unavailable"


def test_ai_judge_invalid_json_falls_back_and_records_status(monkeypatch) -> None:
    class FakeResponse:
        status_code = 200

        def json(self):
            return {"response": "not json"}

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *args, **kwargs):
            return FakeResponse()

    monkeypatch.setenv("AI_SECOND_PASS_ENABLED", "true")
    monkeypatch.setattr(ai_second_pass.httpx, "AsyncClient", FakeAsyncClient)
    ctx = RequestContext(
        method="GET",
        path="/search",
        query_string="q=<script>alert(1)</script>",
        headers={},
        body_preview="",
    )
    verdict = asyncio.run(ai_second_pass.judge_request_with_ai(ctx, []))
    assert verdict is None
    status = ai_second_pass.ai_second_pass_status()
    assert status["last_ok"] is False
    assert status["last_error_type"] == "invalid_json"
