"""AI second-pass request judge for ambiguous WAF cases.

This module is deliberately optional. If the local model is unavailable or
returns invalid JSON, the WAF falls back to the existing rule policy.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

import httpx

from owasp.types import Finding, RequestContext, Severity

_SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}
_SENSITIVE_FIELD_RE = re.compile(
    r'(?i)("?(?:password|passwd|pwd|token|api[_-]?key|secret|session)"?\s*[:=]\s*)("[^"]*"|[^&\s,}]+)'
)
_SUSPICIOUS_RE = re.compile(
    r"(?i)(\bselect\b|\bunion\b|\bor\b\s+1\s*=\s*1|<script|javascript:|../|\.\.\\|%2e%2e|cmd=|exec=|sleep\s*\(|benchmark\s*\(|\{\{.*\}\}|http://|https://)"
)
_TZ_SEOUL = ZoneInfo("Asia/Seoul")
_AI_STATUS_LOCK = threading.Lock()
_AI_STATUS: dict[str, Any] = {
    "last_attempt_iso": "",
    "last_ok": None,
    "last_latency_ms": None,
    "last_error_type": "",
    "last_error_detail": "",
    "last_decision": "never_run",
    "last_confidence": None,
    "last_attack_type": "",
}


@dataclass(frozen=True, slots=True)
class AISecondPassVerdict:
    malicious: bool
    confidence: float
    attack_type: str
    severity: Severity
    reason: str
    recommended_action: str
    raw: dict[str, Any]

    @property
    def should_block(self) -> bool:
        return self.malicious and self.recommended_action == "block"


def _now_iso() -> str:
    return datetime.now(_TZ_SEOUL).strftime("%Y-%m-%d %H:%M:%S")


def _update_ai_status(**fields: Any) -> None:
    with _AI_STATUS_LOCK:
        _AI_STATUS.update(fields)


def _safe_float_env(name: str, default: float, *, lo: float, hi: float) -> float:
    raw = os.environ.get(name, str(default)).strip()
    try:
        return max(lo, min(hi, float(raw)))
    except ValueError:
        return default


def _safe_int_env(name: str, default: int, *, lo: int, hi: int) -> int:
    raw = os.environ.get(name, str(default)).strip()
    try:
        return max(lo, min(hi, int(raw)))
    except ValueError:
        return default


def ai_second_pass_enabled() -> bool:
    return os.environ.get("AI_SECOND_PASS_ENABLED", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def ai_block_min_confidence() -> float:
    return _safe_float_env("AI_BLOCK_MIN_CONFIDENCE", 0.75, lo=0.0, hi=1.0)


def ai_second_pass_status() -> dict[str, Any]:
    """운영 UI/health에 노출할 수 있는 민감정보 없는 AI 상태 snapshot."""
    with _AI_STATUS_LOCK:
        last = dict(_AI_STATUS)
    provider = os.environ.get("AI_PROVIDER", "ollama").strip().lower() or "ollama"
    mode = os.environ.get("AI_SECOND_PASS_MODE", "suspicious").strip().lower() or "suspicious"
    if mode not in {"suspicious", "always"}:
        mode = "suspicious"
    return {
        "enabled": ai_second_pass_enabled(),
        "provider": provider,
        "model": os.environ.get("AI_MODEL", "qwen2.5:7b-instruct").strip()
        or "qwen2.5:7b-instruct",
        "mode": mode,
        "block_min_confidence": ai_block_min_confidence(),
        "timeout_sec": _safe_float_env("AI_SECOND_PASS_TIMEOUT_SEC", 3.0, lo=0.1, hi=60.0),
        "body_max_chars": _safe_int_env(
            "AI_SECOND_PASS_BODY_MAX_CHARS",
            1600,
            lo=128,
            hi=100_000,
        ),
        **last,
    }


def record_ai_final_decision(decision: str, verdict: AISecondPassVerdict | None = None) -> None:
    """WAF gate의 최종 처리 결과를 상태에 반영한다."""
    data: dict[str, Any] = {"last_decision": decision}
    if verdict is not None:
        data["last_confidence"] = verdict.confidence
        data["last_attack_type"] = verdict.attack_type
    _update_ai_status(**data)


def should_run_ai_second_pass(ctx: RequestContext, findings: list[Finding]) -> bool:
    """Limit model calls to requests that are already somewhat suspicious."""
    if not ai_second_pass_enabled():
        _update_ai_status(last_decision="skipped_disabled")
        return False
    mode = os.environ.get("AI_SECOND_PASS_MODE", "suspicious").strip().lower()
    if mode == "always":
        return True
    if findings:
        return True
    sample = "\n".join([ctx.path, ctx.query_string, ctx.body_preview])
    suspicious = bool(_SUSPICIOUS_RE.search(sample))
    if not suspicious:
        _update_ai_status(last_decision="skipped_not_suspicious")
    return suspicious


def _redact_text(value: str, max_len: int) -> str:
    text = _SENSITIVE_FIELD_RE.sub(r"\1[REDACTED]", value or "")
    if len(text) > max_len:
        return text[: max_len - 1] + "…"
    return text


def _safe_headers(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in headers.items():
        lk = key.lower()
        if lk in _SENSITIVE_HEADER_NAMES:
            out[key] = "[REDACTED]"
            continue
        if lk in {"user-agent", "content-type", "accept", "referer", "origin", "host"}:
            out[key] = _redact_text(str(value), 300)
    return out


def _severity_from_ai(value: str) -> Severity:
    key = (value or "").strip().lower()
    try:
        return Severity(key)
    except ValueError:
        return Severity.HIGH


def _payload_for_model(ctx: RequestContext, findings: list[Finding]) -> dict[str, Any]:
    max_body = _safe_int_env("AI_SECOND_PASS_BODY_MAX_CHARS", 1600, lo=128, hi=100_000)
    return {
        "request": {
            "method": ctx.method,
            "path": _redact_text(ctx.path, 500),
            "query_string": _redact_text(ctx.query_string, 1000),
            "headers": _safe_headers(ctx.headers),
            "body_preview": _redact_text(ctx.body_preview, max_body),
        },
        "rule_findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "location": f.location or "",
                "evidence": _redact_text(f.evidence, 500),
            }
            for f in findings[:8]
        ],
    }


def _prompt(ctx: RequestContext, findings: list[Finding]) -> str:
    payload = _payload_for_model(ctx, findings)
    return (
        "You are the second-pass judge for a Web Application Firewall. "
        "Classify whether this HTTP request is malicious. "
        "Return JSON only with keys: malicious(boolean), confidence(number 0..1), "
        "attack_type(string), severity(one of none,low,medium,high,critical), "
        "reason(short string), recommended_action(one of allow,block). "
        "Prefer allow when evidence is weak. Do not include markdown.\n\n"
        f"Input:\n{json.dumps(payload, ensure_ascii=False)}"
    )


def _parse_json_object(text: str) -> dict[str, Any]:
    raw = (text or "").strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        end = raw.rfind("}")
        if start < 0 or end <= start:
            raise
        obj = json.loads(raw[start : end + 1])
    if not isinstance(obj, dict):
        raise ValueError("AI verdict must be a JSON object")
    return obj


async def judge_request_with_ai(
    ctx: RequestContext,
    findings: list[Finding],
) -> AISecondPassVerdict | None:
    """Return an AI verdict, or None when disabled/unavailable/invalid."""
    if not should_run_ai_second_pass(ctx, findings):
        return None
    provider = os.environ.get("AI_PROVIDER", "ollama").strip().lower()
    if provider != "ollama":
        _update_ai_status(
            last_attempt_iso=_now_iso(),
            last_ok=False,
            last_latency_ms=None,
            last_error_type="unsupported_provider",
            last_error_detail=provider[:80],
            last_decision="unavailable",
            last_confidence=None,
            last_attack_type="",
        )
        return None
    base = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434").strip().rstrip("/")
    model = os.environ.get("AI_MODEL", "qwen2.5:7b-instruct").strip()
    timeout = _safe_float_env("AI_SECOND_PASS_TIMEOUT_SEC", 3.0, lo=0.1, hi=60.0)
    started = time.perf_counter()
    _update_ai_status(
        last_attempt_iso=_now_iso(),
        last_ok=None,
        last_latency_ms=None,
        last_error_type="",
        last_error_detail="",
        last_decision="calling",
        last_confidence=None,
        last_attack_type="",
    )
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                f"{base}/api/generate",
                json={
                    "model": model,
                    "prompt": _prompt(ctx, findings),
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0},
                },
            )
        if resp.status_code != 200:
            _update_ai_status(
                last_ok=False,
                last_latency_ms=int((time.perf_counter() - started) * 1000),
                last_error_type="http_error",
                last_error_detail=f"HTTP {resp.status_code}",
                last_decision="unavailable",
            )
            return None
        body = resp.json()
        raw_response = body.get("response") if isinstance(body, dict) else ""
        obj = _parse_json_object(str(raw_response or ""))
        confidence = max(0.0, min(1.0, float(obj.get("confidence", 0.0) or 0.0)))
        action = str(obj.get("recommended_action") or "allow").strip().lower()
        if action not in {"allow", "block"}:
            action = "block" if obj.get("malicious") else "allow"
        verdict = AISecondPassVerdict(
            malicious=bool(obj.get("malicious")),
            confidence=confidence,
            attack_type=str(obj.get("attack_type") or "AI Second Pass").strip()[:80],
            severity=_severity_from_ai(str(obj.get("severity") or "high")),
            reason=str(obj.get("reason") or "").strip()[:400],
            recommended_action=action,
            raw=obj,
        )
        _update_ai_status(
            last_ok=True,
            last_latency_ms=int((time.perf_counter() - started) * 1000),
            last_error_type="",
            last_error_detail="",
            last_decision="block_candidate" if verdict.should_block else "allow",
            last_confidence=verdict.confidence,
            last_attack_type=verdict.attack_type,
        )
        return verdict
    except httpx.TimeoutException:
        _update_ai_status(
            last_ok=False,
            last_latency_ms=int((time.perf_counter() - started) * 1000),
            last_error_type="timeout",
            last_error_detail=f">{timeout:.1f}s",
            last_decision="unavailable",
        )
        return None
    except (json.JSONDecodeError, ValueError) as exc:
        _update_ai_status(
            last_ok=False,
            last_latency_ms=int((time.perf_counter() - started) * 1000),
            last_error_type="invalid_json",
            last_error_detail=str(exc)[:160],
            last_decision="unavailable",
        )
        return None
    except Exception as exc:
        _update_ai_status(
            last_ok=False,
            last_latency_ms=int((time.perf_counter() - started) * 1000),
            last_error_type="request_error",
            last_error_detail=exc.__class__.__name__[:80],
            last_decision="unavailable",
        )
        return None


def verdict_to_finding(verdict: AISecondPassVerdict) -> Finding:
    reason = verdict.reason or "AI second-pass classified this request as malicious."
    evidence = (
        f"confidence={verdict.confidence:.2f}; "
        f"attack_type={verdict.attack_type}; reason={reason}"
    )
    return Finding(
        rule_id="AI-SECOND-PASS",
        evidence=evidence,
        severity=verdict.severity,
        location="ai.second_pass",
    )
