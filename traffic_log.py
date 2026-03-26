"""In-memory ring buffer of recent proxy requests (for dashboard live feed)."""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

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


_EVENTS: deque[TrafficEvent] = deque(maxlen=MAX_EVENTS)


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


async def record(request: Request, *, status_code: int, blocked: bool) -> None:
    if not should_log_path(request.url.path):
        return
    ua = request.headers.get("user-agent") or "—"
    if len(ua) > 220:
        ua = ua[:217] + "…"
    ev = TrafficEvent(
        time_iso=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        client_ip=_client_ip(request),
        method=request.method.upper(),
        path=request.url.path or "/",
        user_agent=ua,
        status_code=int(status_code),
        blocked=blocked,
    )
    async with _LOCK:
        _EVENTS.append(ev)


async def snapshot_dicts() -> list[dict[str, str | int | bool]]:
    async with _LOCK:
        return [asdict(e) for e in reversed(_EVENTS)]
