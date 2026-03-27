"""In-memory ring buffer of recent proxy requests (for dashboard live feed)."""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

TZ_SEOUL = ZoneInfo("Asia/Seoul")

from starlette.requests import Request

MAX_EVENTS = 200
_LOCK = asyncio.Lock()


@dataclass(frozen=True, slots=True)
class TrafficEvent:
    time_iso: str
    client_ip: str
    method: str
    path: str
    user_agent: str
    status_code: int
    blocked: bool
    # 차단 시 탐지 상세(OWASP·유형·위치). 통과 요청은 빈 튜플
    block_findings: tuple[dict[str, str], ...] = ()


_EVENTS: deque[TrafficEvent] = deque(maxlen=MAX_EVENTS)

# 고유 클라이언트(IP 기준) — 프록시 업스트림 요청과 동일 조건으로만 증가
_CLIENT_AGG: dict[str, dict[str, str | int]] = {}


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    rip = request.headers.get("x-real-ip")
    if rip:
        return rip.strip()
    if request.client:
        return request.client.host or "—"
    return "—"


def should_log_path(path: str) -> bool:
    p = path or "/"
    return not (p == "/__proxy" or p.startswith("/__proxy/") or p == "/__waf" or p.startswith("/__waf/"))


def clear() -> None:
    """테스트용 초기화."""
    _EVENTS.clear()
    _CLIENT_AGG.clear()


async def record(
    request: Request,
    *,
    status_code: int,
    blocked: bool,
    block_findings: tuple[dict[str, str], ...] = (),
) -> None:
    if not should_log_path(request.url.path):
        return
    ua = request.headers.get("user-agent") or "—"
    if len(ua) > 220:
        ua = ua[:217] + "…"
    time_iso = datetime.now(TZ_SEOUL).strftime("%Y-%m-%d %H:%M:%S")
    cip = _client_ip(request)
    bf: tuple[dict[str, str], ...] = block_findings if blocked else ()
    ev = TrafficEvent(
        time_iso=time_iso,
        client_ip=cip,
        method=request.method.upper(),
        path=request.url.path or "/",
        user_agent=ua,
        status_code=int(status_code),
        blocked=blocked,
        block_findings=bf,
    )
    async with _LOCK:
        _EVENTS.append(ev)
        row = _CLIENT_AGG.get(cip)
        if row is None:
            _CLIENT_AGG[cip] = {
                "first_seen": time_iso,
                "last_seen": time_iso,
                "requests": 1,
                "user_agent": ua,
            }
        else:
            row["last_seen"] = time_iso
            row["requests"] = int(row["requests"]) + 1
            row["user_agent"] = ua


async def snapshot_dicts() -> list[dict[str, str | int | bool]]:
    async with _LOCK:
        return [asdict(e) for e in reversed(_EVENTS)]


async def clients_snapshot() -> dict[str, Any]:
    async with _LOCK:
        items: list[dict[str, Any]] = []
        for ip, row in _CLIENT_AGG.items():
            items.append({"client_ip": ip, **dict(row)})
        items.sort(key=lambda x: str(x.get("last_seen", "")), reverse=True)
        return {"status": "ok", "unique_clients": len(items), "clients": items}


def _top_counts(counts: dict[str, int], n: int) -> list[dict[str, Any]]:
    items = sorted(counts.items(), key=lambda x: (-x[1], x[0]))[:n]
    return [{"key": k, "count": v} for k, v in items]


async def stats_snapshot() -> dict[str, Any]:
    """버퍼 전체 기준 차단 비율·규칙/공격 유형 상위 N (대시보드 KPI용)."""
    async with _LOCK:
        events = list(_EVENTS)
    total = len(events)
    blocked_n = sum(1 for e in events if e.blocked)
    rule_counts: dict[str, int] = {}
    attack_counts: dict[str, int] = {}
    for e in events:
        if not e.blocked:
            continue
        for bf in e.block_findings:
            if not isinstance(bf, dict):
                continue
            rid = str(bf.get("rule_id") or "").strip()
            if rid:
                rule_counts[rid] = rule_counts.get(rid, 0) + 1
            atk = str(bf.get("attack_type") or "").strip()
            if atk:
                attack_counts[atk] = attack_counts.get(atk, 0) + 1
    ratio = (blocked_n / total) if total else 0.0
    return {
        "status": "ok",
        "buffer_capacity": MAX_EVENTS,
        "total_logged": total,
        "blocked_count": blocked_n,
        "passed_count": total - blocked_n,
        "block_ratio": round(ratio, 4),
        "top_rule_ids": _top_counts(rule_counts, 5),
        "top_attack_types": _top_counts(attack_counts, 5),
    }
