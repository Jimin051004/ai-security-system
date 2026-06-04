"""Reverse proxy: client → WAF scan → UPSTREAM (any origin via UPSTREAM_URL).

이 서버는 단일 사이트의 WAF 프록시 워커입니다.
중앙 대시보드는 별도 dashboard_app.py 를 실행하세요.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent / ".env")
except ImportError:
    pass
from typing import Any
from urllib.parse import quote, urlparse
from zoneinfo import ZoneInfo

import httpx
import jinja2
from fastapi import FastAPI, Request, Response
from markupsafe import Markup
from pydantic import BaseModel, Field
from starlette.datastructures import MutableHeaders
from starlette.middleware.sessions import SessionMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import auth
from ai_second_pass import (
    ai_block_min_confidence,
    ai_second_pass_status,
    judge_request_with_ai,
    record_ai_final_decision,
    verdict_to_finding,
)
from waf_worker_console import attach_worker_console

from detector import (
    all_findings,
    parse_severity,
    scan_request,
    waf_blocking_findings,
)
from owasp.types import Finding, ModuleScanResult, RequestContext, Severity
from request_snapshot import DEFAULT_BODY_PREVIEW_MAX, request_to_context
from waf_block_response import (
    blocking_payload_dict,
    finding_enriched_dict,
    prefer_waf_block_html,
    waf_blocked_html_response,
)
from waf_rule_explain import rule_explain

import traffic_log

# 멀티사이트 레지스트리 (선택적 로드 — 미존재 시 단일 UPSTREAM_URL 모드 유지)
try:
    import site_registry as _site_registry
    _MULTI_SITE_ENABLED = True
except ImportError:
    _site_registry = None  # type: ignore[assignment]
    _MULTI_SITE_ENABLED = False

UPSTREAM_RAW = os.environ.get("UPSTREAM_URL", "http://127.0.0.1:3001").rstrip("/")
_parsed = urlparse(UPSTREAM_RAW)
if not _parsed.scheme or not _parsed.netloc:
    raise SystemExit("UPSTREAM_URL must be a full URL, e.g. http://127.0.0.1:3001")

UPSTREAM_BASE = UPSTREAM_RAW
UPSTREAM_HOST_HEADER = _parsed.netloc
UPSTREAM_ORIGIN = f"{_parsed.scheme}://{_parsed.netloc}".rstrip("/")

# ── 멀티사이트 라우팅 헬퍼 ────────────────────────────────────────────────────

def _resolve_upstream_for_request(request_host: str) -> tuple[str, str, str, str | None]:
    """Host 헤더로 업스트림 URL 결정.

    반환: (upstream_base, upstream_host_header, upstream_origin, route_config_or_None)
    - 등록된 사이트가 있으면 site_registry 에서 조회
    - 없으면 환경변수 UPSTREAM_URL 을 fallback 으로 사용
    """
    if _MULTI_SITE_ENABLED and _site_registry is not None:
        route = _site_registry.lookup_route(request_host)
        if route is not None:
            from urllib.parse import urlparse as _up
            p = _up(route.origin_url)
            host_hdr = p.netloc
            origin = f"{p.scheme}://{p.netloc}".rstrip("/")
            return route.origin_url, host_hdr, origin, route
    return UPSTREAM_BASE, UPSTREAM_HOST_HEADER, UPSTREAM_ORIGIN, None


# 이 프록시가 담당하는 사이트 식별자 (중앙 대시보드에서 구분에 사용)
SITE_ID = os.environ.get("SITE_ID", "default")
# 중앙 사이트 필터에 표시할 이름·주소 (ingest 로 전달; 비우면 Host 기반 URL 만 보냄)
SITE_DISPLAY_NAME = os.environ.get("SITE_DISPLAY_NAME", "").strip()
# 사용자가 .env 등에 명시한 값(.strip() 결과가 빈 문자열이면 「미설정」으로 간주)
CENTRAL_DASHBOARD_URL_EXPLICIT = os.environ.get("CENTRAL_DASHBOARD_URL", "").strip().rstrip("/")
SENSOR_TOKEN_EXPLICIT = os.environ.get("SENSOR_TOKEN", "").strip()

_RESOLVED_INGEST_CACHE: tuple[str, str] | None = None


def _invalidate_resolved_ingest_cache() -> None:
    global _RESOLVED_INGEST_CACHE
    _RESOLVED_INGEST_CACHE = None


def _resolved_central_ingest_pair() -> tuple[str, str]:
    """중앙 ingest URL·토큰. 미설정이면 로컬 데모 기본값(127.0.0.1:8080 + admin sensor_token).

    원격 분리 배포에서는 CENTRAL_DASHBOARD_URL/SENSOR_TOKEN 을 명시하거나,
    WAF_DISABLE_DEFAULT_CENTRAL_INGEST=true 로 자동 채우기를 끄세요.
    """
    global _RESOLVED_INGEST_CACHE
    if _RESOLVED_INGEST_CACHE is not None:
        return _RESOLVED_INGEST_CACHE

    auth.ensure_default_users()

    disable_auto = (
        os.environ.get("WAF_DISABLE_DEFAULT_CENTRAL_INGEST", "").strip().lower()
        in ("1", "true", "yes", "on")
    )

    fallback = (
        os.environ.get("WAF_FALLBACK_CENTRAL_URL", "http://127.0.0.1:8080").strip().rstrip("/")
    )

    if CENTRAL_DASHBOARD_URL_EXPLICIT:
        curl = CENTRAL_DASHBOARD_URL_EXPLICIT
    elif disable_auto:
        curl = ""
    else:
        curl = fallback if fallback else "http://127.0.0.1:8080"

    tok = SENSOR_TOKEN_EXPLICIT
    if not tok and curl:
        cfg = auth.get_sensor_config_for_username("admin")
        if cfg:
            tok = str(cfg.get("sensor_token") or "").strip()

    _RESOLVED_INGEST_CACHE = (curl, tok)
    return curl, tok


# 마지막 중앙 ingest 시도 상태 — GET /__proxy/health (진단). 첫 ingest 전까지는 peek_* 로 해석하세요.
_CENTRAL_INGEST_LAST: dict[str, Any] = {
    "attempted_iso": "",
    "ok": None,
    "http_status": None,
    "detail": "",
}

_TZ_SEOUL = ZoneInfo("Asia/Seoul")
_PROCESS_STARTED_AT = datetime.now(_TZ_SEOUL).strftime("%Y-%m-%d %H:%M:%S")

# LAN 등에서 클라이언트가 프록시 호스트로 접속할 때,
# 업스트림 HTML/JS에 박힌 절대 URL을 공개 origin으로 치환
PROXY_REWRITE_MAX_BYTES = int(os.environ.get("PROXY_REWRITE_MAX_BYTES", str(6 * 1024 * 1024)))


def _waf_enabled() -> bool:
    v = os.environ.get("WAF_ENABLED", "true").strip().lower()
    return v not in ("0", "false", "no", "off")


def _waf_block_min_severity() -> Severity:
    return parse_severity(os.environ.get("WAF_BLOCK_MIN_SEVERITY", "high"), Severity.HIGH)


# 중앙 대시보드에 저장된 사이트별 WAF 정책 (짧게 캐시)
_REMOTE_SITE_WAF: dict[str, Any] = {"t": 0.0, "value": True}
_SITE_WAF_POLICY_TTL = float(os.environ.get("WAF_SITE_POLICY_CACHE_SEC", "3"))


def _follow_central_site_waf_policy() -> bool:
    if os.environ.get("WAF_FOLLOW_SITE_POLICY", "true").strip().lower() in (
        "0",
        "false",
        "no",
        "off",
    ):
        return False
    curl, tok = _resolved_central_ingest_pair()
    return bool(curl and tok)


async def _effective_waf_request_gate_enabled() -> bool:
    """환경변수 WAF 끔 → 항상 False. 중앙 연동 시 사이트별 정책을 주기적으로 조회."""
    if not _waf_enabled():
        return False
    if not _follow_central_site_waf_policy():
        return True
    now = time.monotonic()
    if now - float(_REMOTE_SITE_WAF["t"]) < _SITE_WAF_POLICY_TTL:
        return bool(_REMOTE_SITE_WAF["value"])
    central, tok = _resolved_central_ingest_pair()
    if not central or not tok:
        return True
    url = f"{central}/__waf/api/sensor/site-waf?site={quote(str(SITE_ID).strip(), safe='')}"
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(url, headers={"X-Sensor-Token": tok})
        if resp.status_code == 200:
            raw = resp.json()
            en = bool(raw.get("waf_enabled", True))
            _REMOTE_SITE_WAF["value"] = en
            _REMOTE_SITE_WAF["t"] = now
            return en
    except Exception:
        pass
    _REMOTE_SITE_WAF["t"] = now
    return bool(_REMOTE_SITE_WAF["value"])


def _body_preview_max() -> int:
    raw = os.environ.get("WAF_BODY_PREVIEW_MAX", "").strip()
    if not raw:
        return DEFAULT_BODY_PREVIEW_MAX
    try:
        return max(256, min(int(raw), 1024 * 1024))
    except ValueError:
        return DEFAULT_BODY_PREVIEW_MAX


def _sensor_public_origin_from_request(request: Request) -> str:
    """브라우저 기준 프록시 공개 주소(http(s)://host:port)."""
    xf = (request.headers.get("x-forwarded-proto") or "").strip().lower()
    proto = xf.split(",")[0].strip() if xf else ""
    if proto not in ("http", "https"):
        proto = str(request.url.scheme or "http").lower()
        if proto not in ("http", "https"):
            proto = "http"
    host = (request.headers.get("host") or "").strip()
    if not host and getattr(request.url, "netloc", None):
        host = str(request.url.netloc).strip()
    if not host:
        return ""
    return f"{proto}://{host}".rstrip("/")


def _client_ip_for_log(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    rip = request.headers.get("x-real-ip")
    if rip:
        return rip.strip()
    if request.client:
        return request.client.host or "—"
    return "—"


def _event_payload(
    request: Request,
    *,
    status_code: int,
    blocked: bool,
    block_findings: tuple[dict[str, str], ...] = (),
) -> dict[str, Any]:
    ua = request.headers.get("user-agent") or "—"
    out: dict[str, Any] = {
        "site_id": SITE_ID,
        "time_iso": datetime.now(_TZ_SEOUL).strftime("%Y-%m-%d %H:%M:%S"),
        "client_ip": _client_ip_for_log(request),
        "method": request.method.upper(),
        "path": request.url.path or "/",
        "user_agent": ua[:512],
        "status_code": int(status_code),
        "blocked": bool(blocked),
        "block_findings": [dict(x) for x in (block_findings if blocked else ())],
    }
    if SITE_DISPLAY_NAME:
        out["sensor_label"] = SITE_DISPLAY_NAME[:128]
    spoiler = os.environ.get("SENSOR_PUBLIC_URL", "").strip()
    origin = spoiler or _sensor_public_origin_from_request(request)
    if origin:
        out["sensor_public_origin"] = origin[:512]
    return out


def _truncate_note(s: str, max_len: int = 400) -> str:
    s = (s or "").strip().replace("\n", " ")
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


async def _send_central_log(event: dict[str, Any]) -> None:
    stamp = datetime.now(_TZ_SEOUL).strftime("%Y-%m-%d %H:%M:%S")
    CENTRAL_DASHBOARD_URL, SENSOR_TOKEN = _resolved_central_ingest_pair()
    peek_configured = bool(CENTRAL_DASHBOARD_URL and SENSOR_TOKEN)
    if not peek_configured:
        _CENTRAL_INGEST_LAST.update(
            {
                "configured": False,
                "central_dashboard_url_tail": "",
                "attempted_iso": stamp,
                "ok": False,
                "http_status": None,
                "detail": _truncate_note(
                    "중앙 ingest 비활성: URL 또는 admin sensor_token 없음 "
                    "(WAF_DISABLE_DEFAULT_CENTRAL_INGEST 설정 여부와 waf_auth 내 admin 확인)"
                ),
            }
        )
        return

    url = f"{CENTRAL_DASHBOARD_URL}/__waf/api/ingest"
    payload = dict(event)
    payload["sensor_token"] = SENSOR_TOKEN
    attempt_base = {
        "configured": True,
        "central_dashboard_url_tail": CENTRAL_DASHBOARD_URL[-64:] if CENTRAL_DASHBOARD_URL else "",
        "attempted_iso": stamp,
        "last_ingest_path": str(payload.get("path") or "/")[:256],
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                url,
                json=payload,
                headers={"X-Sensor-Token": SENSOR_TOKEN},
            )
    except Exception as exc:  # noqa: BLE001
        attempt_base.update(
            {
                "ok": False,
                "http_status": None,
                "detail": _truncate_note(str(exc)),
            }
        )
        _CENTRAL_INGEST_LAST.update(attempt_base)
        return

    txt = ""
    try:
        txt = (resp.text or "")[:512]
    except Exception:
        txt = ""

    ok = resp.status_code == 200
    attempt_base.update(
        {
            "ok": ok,
            "http_status": resp.status_code,
            "detail": (
                ""
                if ok
                else _truncate_note(txt or resp.reason_phrase or f"HTTP {resp.status_code}")
            ),
        }
    )
    _CENTRAL_INGEST_LAST.update(attempt_base)
    # 중앙 서버 장애가 실제 사이트 차단/프록시 동작을 막으면 안 된다.


async def _record_proxy_event(
    request: Request,
    *,
    status_code: int,
    blocked: bool,
    block_findings: tuple[dict[str, str], ...] = (),
) -> None:
    await traffic_log.record(
        request,
        status_code=status_code,
        blocked=blocked,
        block_findings=block_findings,
        site_id=SITE_ID,
    )
    await _send_central_log(
        _event_payload(
            request,
            status_code=status_code,
            blocked=blocked,
            block_findings=block_findings,
        )
    )


HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
    }
)

app = FastAPI(
    title="AI Security System — WAF Proxy",
    description=f"Reverse proxy (site: {SITE_ID}) → {UPSTREAM_BASE}",
)
_WAF_SESSION_SECRET = os.environ.get(
    "WAF_SECRET_KEY", "waf-dashboard-dev-secret-change-in-production"
)
app.add_middleware(SessionMiddleware, secret_key=_WAF_SESSION_SECRET, https_only=False)
_BASE = Path(__file__).resolve().parent  # 프로젝트 루트 (dotenv 로드 경로와 동일)


def _tojson_filter(value: Any) -> Markup:
    text = json.dumps(value, ensure_ascii=False, default=str)
    text = text.replace("</", "<\\/")
    return Markup(text)


_jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(_BASE / "templates")),
    autoescape=jinja2.select_autoescape(["html", "xml"]),
)
_jinja_env.filters["tojson"] = _tojson_filter


@app.on_event("startup")
async def _main_startup() -> None:
    auth.ensure_default_users()
    if _MULTI_SITE_ENABLED and _site_registry is not None:
        try:
            _site_registry.init()
        except Exception as _exc:
            import logging as _logging
            _logging.getLogger(__name__).warning("site_registry init failed: %s", _exc)

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
WAF_UI_PREFIX = "/__waf"


def _waf_unknown_path_response() -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content={
            "detail": "Unknown WAF path. Central dashboard UI is on the dashboard server; "
            "on this proxy worker use /__waf/worker/logs (admin) for local SQLite traffic."
        },
        headers={"Cache-Control": "no-store"},
    )


def _upstream_headers(request: Request) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in request.headers.items():
        lk = key.lower()
        if lk in HOP_BY_HOP:
            continue
        if lk == "accept-encoding":
            continue
        out[key] = value
    out["host"] = UPSTREAM_HOST_HEADER
    out["accept-encoding"] = "identity"
    return out


def _request_public_origin(request: Request) -> str:
    u = request.url
    return f"{u.scheme}://{u.netloc}".rstrip("/")


def _upstream_origin_variants() -> list[str]:
    """UPSTREAM_URL 과 같은 서버를 가리키는 localhost / 127.0.0.1 표기."""
    variants = [UPSTREAM_ORIGIN]
    host = (_parsed.hostname or "").lower()
    scheme = (_parsed.scheme or "http").lower()
    port = _parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80
    if host in ("127.0.0.1", "localhost"):
        alt = "localhost" if host == "127.0.0.1" else "127.0.0.1"
        variants.append(f"{scheme}://{alt}:{port}")
    out: list[str] = []
    seen: set[str] = set()
    for v in variants:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _rewrite_location_header(value: str, request: Request) -> str:
    pub = _request_public_origin(request)
    v = (value or "").strip()
    for orig in sorted(_upstream_origin_variants(), key=len, reverse=True):
        if v.startswith(orig):
            return pub + v[len(orig):]
    return value


def _media_type_should_rewrite_body(ct_header: str) -> bool:
    main = (ct_header or "").split(";")[0].strip().lower()
    if main in ("text/html", "application/json", "text/css"):
        return True
    if "javascript" in main or "ecmascript" in main:
        return True
    return False


def _inject_waf_interceptor(text: str, content_type: str) -> tuple[str, bool]:
    """업스트림 HTML에 XHR/fetch 차단 응답용 리다이렉트 스크립트를 삽입."""
    main = (content_type or "").split(";")[0].strip().lower()
    if main != "text/html" or "waf_proxy_interceptor.js" in text:
        return text, False
    tag = '<script src="/__waf/static/js/waf_proxy_interceptor.js" defer></script>'
    lower = text.lower()
    idx = lower.rfind("</body>")
    if idx >= 0:
        return text[:idx] + tag + text[idx:], True
    idx = lower.rfind("</head>")
    if idx >= 0:
        return text[:idx] + tag + text[idx:], True
    return text + tag, True


def _rewrite_response_body_for_public_origin(
    content: bytes, content_type: str, request: Request
) -> tuple[bytes, bool]:
    """본문 치환 및(HTML이면) 인터셉터 스크립트 주입. 둘째 값=True면 CSP 제거 등이 필요할 수 있음."""
    if len(content) > PROXY_REWRITE_MAX_BYTES:
        return content, False
    if not _media_type_should_rewrite_body(content_type):
        return content, False
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return content, False
    pub = _request_public_origin(request)
    changed = False
    for orig in sorted(_upstream_origin_variants(), key=len, reverse=True):
        if orig in text:
            text = text.replace(orig, pub)
            changed = True
    text, injected = _inject_waf_interceptor(text, content_type)
    changed = changed or injected
    if not changed:
        return content, False
    return text.encode("utf-8"), injected


def _build_proxied_upstream_response(request: Request, upstream: httpx.Response) -> Response:
    ct = upstream.headers.get("content-type", "")
    content, interceptor_injected = _rewrite_response_body_for_public_origin(
        upstream.content, ct, request
    )
    out = MutableHeaders()
    for key, value in upstream.headers.multi_items():
        lk = key.lower()
        if lk in HOP_BY_HOP:
            continue
        if lk in ("content-length", "content-encoding", "transfer-encoding"):
            continue
        if lk == "content-security-policy" and interceptor_injected:
            continue
        if lk == "location":
            value = _rewrite_location_header(value, request)
        out.append(key, value)
    return Response(
        content=content,
        status_code=upstream.status_code,
        headers=out,
    )


async def _forward(request: Request, full_path: str, upstream_base: str | None = None, upstream_host: str | None = None) -> Response:
    _base = upstream_base or UPSTREAM_BASE
    _host = upstream_host or UPSTREAM_HOST_HEADER
    path = full_path.lstrip("/")
    url = f"{_base}/{path}" if path else _base
    if request.url.query:
        url = f"{url}?{request.url.query}"

    body = await request.body()
    # 동적 upstream으로 헤더 재구성
    headers_dict: dict[str, str] = {}
    for key, value in request.headers.items():
        lk = key.lower()
        if lk in HOP_BY_HOP or lk == "accept-encoding":
            continue
        headers_dict[key] = value
    headers_dict["host"] = _host
    headers_dict["accept-encoding"] = "identity"
    headers = headers_dict

    async with httpx.AsyncClient(follow_redirects=False) as client:
        try:
            upstream = await client.request(
                request.method,
                url,
                headers=headers if isinstance(headers, dict) else dict(headers),
                content=body if body else None,
                timeout=httpx.Timeout(60.0),
            )
        except httpx.RequestError as exc:
            return Response(
                content=f"Upstream unreachable: {exc}".encode(),
                status_code=502,
                media_type="text/plain; charset=utf-8",
            )

    return _build_proxied_upstream_response(request, upstream)


async def _run_waf_gate(
    request: Request,
) -> tuple[Response | None, list[ModuleScanResult], list[Finding]]:
    """스캔 후 차단이면 403 응답과 함께 탐지 목록을 반환. 통과면 (None, results, [])."""
    if not await _effective_waf_request_gate_enabled():
        return None, [], []
    ctx = await request_to_context(request, body_preview_max=_body_preview_max())
    results = await scan_request(ctx)
    findings = all_findings(results)
    min_sev = _waf_block_min_severity()
    blocking = waf_blocking_findings(findings, min_sev)
    if not blocking:
        ai_verdict = await judge_request_with_ai(ctx, findings)
        if (
            ai_verdict is None
            or not ai_verdict.should_block
            or ai_verdict.confidence < ai_block_min_confidence()
        ):
            if ai_verdict is not None:
                if ai_verdict.should_block:
                    record_ai_final_decision("allow_low_confidence", ai_verdict)
                else:
                    record_ai_final_decision("allow", ai_verdict)
            return None, results, []
        ai_finding = verdict_to_finding(ai_verdict)
        record_ai_final_decision("block", ai_verdict)
        results = [
            *results,
            ModuleScanResult("ai", "AI", (ai_finding,)),
        ]
        blocking = [ai_finding]
    payload = blocking_payload_dict(
        results,
        blocking,
        min_sev,
        upstream_base=UPSTREAM_BASE,
    )
    if prefer_waf_block_html(request):
        blocked: Response = waf_blocked_html_response(payload, jinja_env=_jinja_env)
    else:
        blocked = JSONResponse(status_code=403, content=payload)
    return blocked, results, blocking


@app.get("/__proxy/health")
async def proxy_health() -> dict[str, Any]:
    db_hint = (
        os.environ.get("TRAFFIC_LOG_DB", "").strip()
        or str(Path(__file__).resolve().parent / "waf_traffic.sqlite3")
    )
    curl, ctok = _resolved_central_ingest_pair()
    peek_configured = bool(curl and ctok)

    merged = dict(_CENTRAL_INGEST_LAST)

    merged_peek = {
        **merged,
        "peek_configured": peek_configured,
        "explicit_central_dashboard_url_was_set": bool(CENTRAL_DASHBOARD_URL_EXPLICIT),
        "explicit_sensor_token_was_set": bool(SENSOR_TOKEN_EXPLICIT),
        "auto_fallback_central_dashboard_url_used": peek_configured
        and bool(curl)
        and (not CENTRAL_DASHBOARD_URL_EXPLICIT),
        "auto_admin_sensor_token_used": peek_configured and bool(ctok) and (not SENSOR_TOKEN_EXPLICIT),
        "resolved_central_dashboard_url_tail": curl[-64:] if curl else "",
        "explain": (
            "로컬 데모: CENTRAL 미지정 시 http://127.0.0.1:8080 + waf_auth 의 admin sensor_token 로 자동 ingest. "
            "원격에는 CENTRAL/SENSOR 명시 또는 WAF_DISABLE_DEFAULT_CENTRAL_INGEST 로 끔. "
            "같은 머신이어도 프록시·대시보드가 같은 TRAFFIC_LOG_DB 또는 ingest 가 있어야 8080에 보입니다."
        ),
        "open_health_url_relative": "/__proxy/health",
        "central_traffic_dashboard_url": (f"{curl}/__waf/dashboard/traffic" if curl else ""),
    }
    if "configured" in merged:
        merged_peek["configured"] = merged["configured"]
    else:
        merged_peek["configured"] = peek_configured
    if "configured" not in merged and peek_configured:
        merged_peek.setdefault(
            "detail",
            "아직 ingest 시도 없음. 트래픽 한 건 보낸 뒤 ok/http_status 확인.",
        )
    return {
        "status": "ok",
        "site_id": SITE_ID,
        "upstream": UPSTREAM_BASE,
        "waf_enabled": _waf_enabled(),
        "waf_follows_central_site_policy": _follow_central_site_waf_policy(),
        "waf_site_policy_ttl_sec": _SITE_WAF_POLICY_TTL,
        "waf_request_gate_cached": await _effective_waf_request_gate_enabled(),
        "waf_block_min_severity": _waf_block_min_severity().value,
        "process_started_at": _PROCESS_STARTED_AT,
        "local_traffic_db_hint": db_hint,
        "central_ingest": merged_peek,
        "ai_second_pass": ai_second_pass_status(),
    }


@app.get("/__waf/blocked")
async def waf_blocked_interceptor_landing(request: Request) -> HTMLResponse:
    """fetch/XHR 403 JSON 후 인터셉터가 이동하는 차단 전용 HTML."""
    p = request.query_params
    has_row = bool(
        (p.get("rule_id") or "").strip()
        or (p.get("owasp_id") or "").strip()
        or (p.get("attack_type") or "").strip()
    )
    if not has_row:
        return waf_blocked_html_response(
            {
                "blocked": True,
                "policy": "interceptor_redirect",
                "min_severity": _waf_block_min_severity().value,
                "upstream": UPSTREAM_BASE,
                "findings": [],
            },
            jinja_env=_jinja_env,
        )
    owasp_id = p.get("owasp_id") or "—"
    category = p.get("category") or "—"
    atk = p.get("attack_type") or "알 수 없는 공격 유형"
    rule_id = p.get("rule_id") or "—"
    severity_raw = (p.get("severity") or "high").strip().lower()
    if severity_raw not in ("none", "low", "medium", "high", "critical"):
        severity_raw = "high"
    location = p.get("location") or "—"
    evidence = p.get("evidence") or "—"
    row: dict[str, str] = {
        "owasp_id": owasp_id,
        "category": category,
        "attack_type": atk,
        "rule_id": rule_id,
        "severity": severity_raw,
        "location": location,
        "evidence": evidence,
        "rule_explain": rule_explain(rule_id, evidence),
    }
    return waf_blocked_html_response(
        {
            "blocked": True,
            "policy": "interceptor_redirect",
            "min_severity": _waf_block_min_severity().value,
            "upstream": UPSTREAM_BASE,
            "findings": [row],
        },
        jinja_env=_jinja_env,
    )


class FragmentScanIn(BaseModel):
    """인터셉터가 location.hash 를 서버로 넘겨 WAF 가 스캔할 때 사용."""

    fragment: str = Field(default="", max_length=16384)


@app.post("/__waf/api/scan-fragment", response_model=None)
async def waf_api_scan_fragment(body: FragmentScanIn) -> Any:
    raw = body.fragment or ""
    if not raw.strip():
        return {"status": "ok"}
    if not await _effective_waf_request_gate_enabled():
        return {"status": "ok"}
    ctx = RequestContext(
        method="GET",
        path="/",
        query_string="",
        headers={},
        body_preview=raw[: _body_preview_max()],
    )
    results = await scan_request(ctx)
    findings = all_findings(results)
    blocking = waf_blocking_findings(findings, _waf_block_min_severity())
    if not blocking:
        return {"status": "ok"}
    payload = blocking_payload_dict(
        results,
        blocking,
        _waf_block_min_severity(),
        upstream_base=UPSTREAM_BASE,
    )
    return JSONResponse(status_code=403, content=payload)


# `/__waf/{waf_tail:path}` 보다 먼저 등록해야 정적 파일이 404로 가지 않음
_WAF_STATIC_DIR = _BASE / "static" / "waf"
app.mount(
    "/__waf/static",
    StaticFiles(directory=str(_WAF_STATIC_DIR)),
    name="waf_static",
)

attach_worker_console(app, _jinja_env)


@app.get("/__waf/api/tls-check", include_in_schema=False)
async def _main_tls_domain_check(domain: str = "") -> Response:
    """Caddy on-demand TLS 검증 — WAF에 등록된 도메인만 cert 발급 허용."""
    if not domain:
        return Response(status_code=400, content="domain parameter required")
    clean = domain.split(":")[0].strip().lower()
    if not clean:
        return Response(status_code=400, content="invalid domain")
    if _MULTI_SITE_ENABLED and _site_registry:
        route = _site_registry.lookup_route(clean)
        if route is None:
            return Response(status_code=403, content="domain not registered")
        return Response(status_code=200, content="ok")
    # site_registry 없음 (싱글사이트 모드) — 일단 허용
    return Response(status_code=200, content="ok")


@app.api_route("/__waf", methods=METHODS)
@app.api_route("/__waf/", methods=METHODS)
async def waf_reserved_root(_request: Request) -> JSONResponse:
    return _waf_unknown_path_response()


@app.api_route("/__waf/{waf_tail:path}", methods=METHODS)
async def waf_reserved_subpath(waf_tail: str, _request: Request) -> JSONResponse:
    return _waf_unknown_path_response()


@app.api_route("/", methods=METHODS)
async def proxy_root(request: Request) -> Response:
    _host = request.headers.get("host", "")
    _upstream_base, _upstream_host, _upstream_origin, _route = _resolve_upstream_for_request(_host)
    # IP 정책 체크
    if _route and _MULTI_SITE_ENABLED and _site_registry:
        _client_ip = _client_ip_for_log(request)
        _ip_action = _site_registry.check_ip_policy(_route.site_id, _client_ip)
        if _ip_action == "block":
            await _record_proxy_event(request, status_code=403, blocked=True)
            return JSONResponse(status_code=403, content={"detail": "IP 차단 정책에 의해 차단되었습니다.", "blocked": True})
        if _ip_action == "allow":
            resp = await _forward(request, "", upstream_base=_upstream_base, upstream_host=_upstream_host)
            await _record_proxy_event(request, status_code=resp.status_code, blocked=False)
            return resp
    # 예외 경로 체크
    if _route and _MULTI_SITE_ENABLED and _site_registry:
        if _site_registry.is_exception_path(_route.site_id, request.url.path, request.method):
            resp = await _forward(request, "", upstream_base=_upstream_base, upstream_host=_upstream_host)
            await _record_proxy_event(request, status_code=resp.status_code, blocked=False)
            return resp
    # detect 모드면 WAF 게이트 통과 후 로그만
    if _route and _route.mode == "disabled":
        resp = await _forward(request, "", upstream_base=_upstream_base, upstream_host=_upstream_host)
        await _record_proxy_event(request, status_code=resp.status_code, blocked=False)
        return resp
    blocked, scan_results, blocking_findings = await _run_waf_gate(request)
    if blocked is not None and (_route is None or _route.mode == "block"):
        rows = tuple(
            finding_enriched_dict(scan_results, f, evidence_max=400)
            for f in blocking_findings
        )
        await _record_proxy_event(
            request, status_code=403, blocked=True, block_findings=rows
        )
        return blocked
    resp = await _forward(request, "", upstream_base=_upstream_base, upstream_host=_upstream_host)
    await _record_proxy_event(request, status_code=resp.status_code, blocked=False)
    return resp


@app.api_route("/{full_path:path}", methods=METHODS)
async def proxy_path(full_path: str, request: Request) -> Response:
    if full_path == "__proxy" or full_path.startswith("__proxy/"):
        return Response(status_code=404)
    if full_path == "__waf" or full_path.startswith("__waf/"):
        return _waf_unknown_path_response()
    _host = request.headers.get("host", "")
    _upstream_base, _upstream_host, _upstream_origin, _route = _resolve_upstream_for_request(_host)
    # IP 정책 체크
    if _route and _MULTI_SITE_ENABLED and _site_registry:
        _client_ip = _client_ip_for_log(request)
        _ip_action = _site_registry.check_ip_policy(_route.site_id, _client_ip)
        if _ip_action == "block":
            await _record_proxy_event(request, status_code=403, blocked=True)
            return JSONResponse(status_code=403, content={"detail": "IP 차단 정책에 의해 차단되었습니다.", "blocked": True})
        if _ip_action == "allow":
            resp = await _forward(request, full_path, upstream_base=_upstream_base, upstream_host=_upstream_host)
            await _record_proxy_event(request, status_code=resp.status_code, blocked=False)
            return resp
    # 예외 경로
    if _route and _MULTI_SITE_ENABLED and _site_registry:
        if _site_registry.is_exception_path(_route.site_id, "/" + full_path, request.method):
            resp = await _forward(request, full_path, upstream_base=_upstream_base, upstream_host=_upstream_host)
            await _record_proxy_event(request, status_code=resp.status_code, blocked=False)
            return resp
    if _route and _route.mode == "disabled":
        resp = await _forward(request, full_path, upstream_base=_upstream_base, upstream_host=_upstream_host)
        await _record_proxy_event(request, status_code=resp.status_code, blocked=False)
        return resp
    blocked, scan_results, blocking_findings = await _run_waf_gate(request)
    if blocked is not None and (_route is None or _route.mode == "block"):
        rows = tuple(
            finding_enriched_dict(scan_results, f, evidence_max=400)
            for f in blocking_findings
        )
        await _record_proxy_event(
            request, status_code=403, blocked=True, block_findings=rows
        )
        return blocked
    resp = await _forward(request, full_path, upstream_base=_upstream_base, upstream_host=_upstream_host)
    await _record_proxy_event(request, status_code=resp.status_code, blocked=False)
    return resp
