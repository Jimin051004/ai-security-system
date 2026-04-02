"""Reverse proxy: client → WAF scan → UPSTREAM (any origin via UPSTREAM_URL)."""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

import httpx
from pydantic import BaseModel, Field
import jinja2
from fastapi import FastAPI, HTTPException, Request, Response
from starlette.datastructures import MutableHeaders
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from detector import (
    all_findings,
    findings_at_or_above_severity,
    parse_severity,
    scan_request,
)
from owasp import MODULES
from owasp.types import Finding, ModuleScanResult, Severity
from request_snapshot import DEFAULT_BODY_PREVIEW_MAX, request_to_context

import traffic_log

UPSTREAM_RAW = os.environ.get("UPSTREAM_URL", "http://127.0.0.1:3001").rstrip("/")
_parsed = urlparse(UPSTREAM_RAW)
if not _parsed.scheme or not _parsed.netloc:
    raise SystemExit("UPSTREAM_URL must be a full URL, e.g. http://127.0.0.1:3001")

UPSTREAM_BASE = UPSTREAM_RAW
UPSTREAM_HOST_HEADER = _parsed.netloc
UPSTREAM_ORIGIN = f"{_parsed.scheme}://{_parsed.netloc}".rstrip("/")

# LAN 등에서 클라이언트가 프록시 호스트(예: 192.168.x.x:8080)로 접속할 때,
# 업스트림 HTML/JS에 박힌 http://127.0.0.1:3001 절대 URL 때문에 브라우저가 로컬로 요청하는 문제 방지
PROXY_REWRITE_MAX_BYTES = int(os.environ.get("PROXY_REWRITE_MAX_BYTES", str(6 * 1024 * 1024)))


def _waf_enabled() -> bool:
    v = os.environ.get("WAF_ENABLED", "true").strip().lower()
    return v not in ("0", "false", "no", "off")


def _waf_block_min_severity() -> Severity:
    return parse_severity(os.environ.get("WAF_BLOCK_MIN_SEVERITY", "high"), Severity.HIGH)


def _body_preview_max() -> int:
    raw = os.environ.get("WAF_BODY_PREVIEW_MAX", "").strip()
    if not raw:
        return DEFAULT_BODY_PREVIEW_MAX
    try:
        return max(256, min(int(raw), 1024 * 1024))
    except ValueError:
        return DEFAULT_BODY_PREVIEW_MAX


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

app = FastAPI(title="AI Security System", description="Reverse proxy to upstream web app")
_BASE = Path(__file__).resolve().parent
_jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(_BASE / "templates")),
    autoescape=jinja2.select_autoescape(["html", "xml"]),
)

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

# Juice Shop 등 업스트림에도 /dashboard·/api/... 가 있어 catch-all에 먹히면 프록시 UI 대신 업스트림이 뜸.
# 프록시 전용 UI는 항상 이 접두사(및 아래 예외 경로)로만 노출.
WAF_UI_PREFIX = "/__waf"

_PROCESS_STARTED_AT = datetime.now(ZoneInfo("Asia/Seoul")).strftime("%Y-%m-%d %H:%M:%S")


def _normalize_proxy_path_segment(full_path: str) -> str:
    """catch-all 에서 온 하위 경로 정규화 (끝 슬래시·대소문자 비교용)."""
    return (full_path or "").strip().rstrip("/")


def _is_waf_dashboard_path(norm: str) -> bool:
    n = norm.casefold()
    return n == "dashboard" or n == "__waf/dashboard"


def _is_waf_summary_api_path(norm: str) -> bool:
    n = norm.casefold()
    return n in ("api/dashboard/summary", "__waf/api/summary")


async def _probe_upstream() -> tuple[bool, str]:
    """업스트림에 연결 가능한지 확인(404 등은 서버가 살아 있는 것으로 간주, 5xx·연결 실패만 불량)."""
    timeout = httpx.Timeout(3.0)
    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            r = await client.head(UPSTREAM_BASE, timeout=timeout)
            if r.status_code == 405:
                r = await client.get(UPSTREAM_BASE, timeout=timeout)
            ok = r.status_code < 500
            return (ok, "" if ok else f"HTTP {r.status_code}")
    except httpx.HTTPError as exc:
        return (False, str(exc)[:200])
    except OSError as exc:
        return (False, str(exc)[:200])


def _dashboard_summary_dict(*, upstream_ok: bool, upstream_error: str) -> dict[str, Any]:
    return {
        "status": "ok",
        "upstream": UPSTREAM_BASE,
        "upstream_ok": upstream_ok,
        "upstream_error": upstream_error,
        "waf_enabled": _waf_enabled(),
        "waf_block_min_severity": _waf_block_min_severity().value,
        "body_preview_max": _body_preview_max(),
    }


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


def _access_snapshot(request: Request) -> dict[str, Any]:
    u = request.url
    return {
        "client_ip": _client_ip(request),
        "x_forwarded_for": request.headers.get("x-forwarded-for") or "",
        "x_real_ip": request.headers.get("x-real-ip") or "",
        "user_agent": request.headers.get("user-agent") or "—",
        "method": request.method,
        "path": u.path,
        "full_url": str(u),
        "host_header": request.headers.get("host") or "—",
        "referer": request.headers.get("referer") or "—",
        "accept_language": request.headers.get("accept-language") or "—",
    }


def _upstream_headers(request: Request) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in request.headers.items():
        if key.lower() in HOP_BY_HOP:
            continue
        out[key] = value
    out["host"] = UPSTREAM_HOST_HEADER
    return out


def _request_public_origin(request: Request) -> str:
    u = request.url
    return f"{u.scheme}://{u.netloc}".rstrip("/")


def _upstream_origin_variants() -> list[str]:
    """UPSTREAM_URL 과 같은 서버를 가리키는 localhost / 127.0.0.1 표기 (SPA 번들·리다이렉트에 섞임)."""
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
            return pub + v[len(orig) :]
    return value


def _media_type_should_rewrite_body(ct_header: str) -> bool:
    main = (ct_header or "").split(";")[0].strip().lower()
    if main in ("text/html", "application/json", "text/css"):
        return True
    if "javascript" in main or "ecmascript" in main:
        return True
    return False


# Juice Shop 프록시 HTML에 주입할 WAF 인터셉터 스크립트.
# fetch / XMLHttpRequest 403 응답을 감지해 /__waf/blocked 차단 페이지로 리다이렉트.
_WAF_INTERCEPTOR_JS = """
<script id="__waf-interceptor">
(function(){
  function _wafRedirect(data) {
    if (!data || !data.blocked) return;
    var f = (data.findings && data.findings[0]) || {};
    var p = new URLSearchParams({
      owasp_id:    f.owasp_id    || '',
      category:    f.category    || '',
      attack_type: f.attack_type || 'WAF 차단',
      rule_id:     f.rule_id     || '',
      severity:    f.severity    || 'high',
      location:    f.location    || '',
      evidence:    (f.evidence   || '').slice(0, 200),
    });
    window.location.href = '/__waf/blocked?' + p.toString();
  }

  /* fetch 인터셉터 */
  var _origFetch = window.fetch;
  window.fetch = function(input, init) {
    return _origFetch.call(this, input, init).then(function(resp) {
      if (resp.status === 403) {
        resp.clone().json().then(_wafRedirect).catch(function(){});
      }
      return resp;
    });
  };

  /* XMLHttpRequest 인터셉터 */
  var _origOpen = XMLHttpRequest.prototype.open;
  var _origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function(m, u) {
    this._wafUrl = u;
    return _origOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function() {
    this.addEventListener('load', function() {
      if (this.status === 403) {
        try { _wafRedirect(JSON.parse(this.responseText)); } catch(e) {}
      }
    });
    return _origSend.apply(this, arguments);
  };
})();
</script>"""


def _inject_waf_interceptor(text: str) -> str:
    """HTML </body> 직전에 WAF 인터셉터 스크립트를 삽입한다."""
    tag = "</body>"
    idx = text.lower().rfind(tag)
    if idx == -1:
        return text + _WAF_INTERCEPTOR_JS
    return text[:idx] + _WAF_INTERCEPTOR_JS + text[idx:]


def _rewrite_response_body_for_public_origin(
    content: bytes, content_type: str, request: Request
) -> bytes:
    if len(content) > PROXY_REWRITE_MAX_BYTES:
        return content
    if not _media_type_should_rewrite_body(content_type):
        return content
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return content
    main_ct = (content_type or "").split(";")[0].strip().lower()
    # URL 재작성
    pub = _request_public_origin(request)
    for orig in sorted(_upstream_origin_variants(), key=len, reverse=True):
        if orig in text:
            text = text.replace(orig, pub)
    # HTML 응답에만 WAF 인터셉터 삽입
    if main_ct == "text/html" and "__waf-interceptor" not in text:
        text = _inject_waf_interceptor(text)
    return text.encode("utf-8")


def _build_proxied_upstream_response(request: Request, upstream: httpx.Response) -> Response:
    ct = upstream.headers.get("content-type", "")
    content = _rewrite_response_body_for_public_origin(upstream.content, ct, request)
    # Starlette Response.headers 는 Mapping 만 허용 — list/tuple 이면 500 (AttributeError)
    out = MutableHeaders()
    for key, value in upstream.headers.multi_items():
        lk = key.lower()
        if lk in HOP_BY_HOP:
            continue
        if lk in ("content-length", "content-encoding", "transfer-encoding"):
            continue
        if lk == "location":
            value = _rewrite_location_header(value, request)
        out.append(key, value)
    return Response(
        content=content,
        status_code=upstream.status_code,
        headers=out,
    )


async def _forward(request: Request, full_path: str) -> Response:
    path = full_path.lstrip("/")
    url = f"{UPSTREAM_BASE}/{path}" if path else UPSTREAM_BASE
    if request.url.query:
        url = f"{url}?{request.url.query}"

    body = await request.body()
    headers = _upstream_headers(request)

    async with httpx.AsyncClient(follow_redirects=False) as client:
        try:
            upstream = await client.request(
                request.method,
                url,
                headers=headers,
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


def _module_for_rule(results: list[ModuleScanResult], rule_id: str) -> ModuleScanResult | None:
    for r in results:
        if any(x.rule_id == rule_id for x in r.findings):
            return r
    return None


def _module_title(module_id: str) -> str:
    for m in MODULES:
        if m.module_id == module_id:
            return m.title
    return "—"


def _attack_type_label(rule_id: str) -> str:
    u = rule_id.upper()
    # A05:2025 — Injection
    if u.startswith("A05-SQL"):
        return "SQL Injection"
    if u.startswith("A05-CMD"):
        return "OS Command Injection"
    if u.startswith("A05-XSS"):
        return "Cross-Site Scripting (XSS)"
    if u.startswith("A05-LDAP"):
        return "LDAP Injection"
    if u.startswith("A05-XPATH"):
        return "XPath Injection"
    if u.startswith("A05-EL"):
        return "Expression Language Injection"
    if u.startswith("A05-SSTI"):
        return "Server-Side Template Injection (SSTI)"
    if u.startswith("A05-CRLF"):
        return "CRLF Injection"
    # A06:2025 — Insecure Design
    if u.startswith("A06-ROLE"):
        return "Role/Privilege Escalation"
    if u.startswith("A06-PRICE"):
        return "Price / Amount Manipulation"
    if u.startswith("A06-MASS"):
        return "Mass Assignment (Protected Field)"
    if u.startswith("A06-ADMIN"):
        return "Admin Endpoint Direct Access"
    if u.startswith("A06-STEP"):
        return "Workflow Step Skipping"
    if u.startswith("A06-RATE"):
        return "Rate Limit Abuse (Brute-force)"
    # A10:2025 — Mishandling of Exceptional Conditions
    if u.startswith("A10-UNDEF"):
        return "Undefined Identifier (예외 미처리)"
    if u.startswith("A10-PROTO"):
        return "Prototype Pollution"
    if u.startswith("A10-BOUND"):
        return "Boundary Value / Integer Overflow"
    if u.startswith("A10-NULLB"):
        return "Null-Byte Injection"
    if u.startswith("A10-FMT"):
        return "Format String Probe"
    if u.startswith("A10-DEEP"):
        return "Deep Nesting / DoS"
    if u.startswith("A10-TYPECONF"):
        return "Type Confusion"
    if u.startswith("A10-ERRPRB"):
        return "Error Probe (예외 조건 유발)"
    if u.startswith("A10-HDRNOM"):
        return "HTTP Header Anomaly"
    return "기타 / 규칙 기반 탐지"


def _finding_enriched_dict(
    results: list[ModuleScanResult],
    f: Finding,
    *,
    evidence_max: int = 500,
) -> dict[str, str]:
    mod = _module_for_rule(results, f.rule_id)
    owasp_id = mod.owasp_id if mod else "—"
    category = _module_title(mod.module_id) if mod else "—"
    ev = f.evidence
    if len(ev) > evidence_max:
        ev = ev[: evidence_max - 1] + "…"
    return {
        "owasp_id": owasp_id,
        "category": category,
        "attack_type": _attack_type_label(f.rule_id),
        "rule_id": f.rule_id,
        "severity": f.severity.value,
        "location": f.location or "—",
        "evidence": ev,
    }


def _blocking_payload_dict(
    results: list[ModuleScanResult],
    blocking: list[Finding],
    min_sev: Severity,
) -> dict[str, Any]:
    return {
        "blocked": True,
        "policy": "min_severity",
        "min_severity": min_sev.value,
        "upstream": UPSTREAM_BASE,
        "findings": [_finding_enriched_dict(results, f) for f in blocking],
    }


def _prefer_waf_block_html(request: Request) -> bool:
    """브라우저 주소창 직접 탐색(sec-fetch-dest: document)만 HTML 차단 페이지 반환.
    XHR / fetch API 호출은 JSON 403 반환 → 삽입된 인터셉터 JS 가 /__waf/blocked 로 리다이렉트.
    """
    fmt = (request.query_params.get("__waf_block_format") or "").lower()
    if fmt == "json":
        return False
    if fmt == "html":
        return True
    dest = (request.headers.get("sec-fetch-dest") or "").lower()
    return dest == "document"


def _waf_blocked_html_response(payload: dict[str, Any]) -> HTMLResponse:
    rows: list[dict[str, str]] = list(payload.get("findings") or [])
    if not rows:
        headline = "위협 패턴이 탐지되어 차단되었습니다"
        subline = "요청 본문·URL 등에서 차단 기준에 해당하는 입력이 확인되었습니다."
        alert_message = f"[WAF 차단] {headline}\n{subline}"
    elif len(rows) == 1:
        f0 = rows[0]
        atk = f0.get("attack_type") or "알 수 없는 공격 유형"
        headline = f"{atk} 취약점이 발견되어 차단되었습니다"
        subline = (
            f"OWASP {f0.get('owasp_id', '—')} · {f0.get('category', '—')} · "
            f"규칙 {f0.get('rule_id', '—')} · 탐지 위치 {f0.get('location', '—')}"
        )
        alert_message = f"[WAF 차단] {headline}\n{subline}"
    else:
        types: list[str] = []
        seen_t: set[str] = set()
        for r in rows:
            t = r.get("attack_type") or "—"
            if t not in seen_t:
                seen_t.add(t)
                types.append(t)
        types_str = ", ".join(types[:4])
        if len(types) > 4:
            types_str += f" 외 {len(types) - 4}종"
        headline = "복수 취약점 패턴이 발견되어 차단되었습니다"
        subline = f"탐지된 유형: {types_str} (총 {len(rows)}건 규칙 매칭)"
        alert_message = f"[WAF 차단] {headline}\n{subline}"
    tpl = _jinja_env.get_template("waf_blocked.html")
    html = tpl.render(
        rows=rows,
        boot={"alert_message": alert_message},
        headline=headline,
        subline=subline,
    )
    return HTMLResponse(
        content=html,
        status_code=403,
        headers={"Cache-Control": "no-store"},
    )


async def _run_waf_gate(
    request: Request,
) -> tuple[Response | None, list[ModuleScanResult], list[Finding]]:
    """스캔 후 차단이면 403 응답과 함께 탐지 목록을 반환. 통과면 (None, results, [])."""
    if not _waf_enabled():
        return None, [], []
    ctx = await request_to_context(request, body_preview_max=_body_preview_max())
    results = await scan_request(ctx)
    findings = all_findings(results)
    min_sev = _waf_block_min_severity()
    blocking = findings_at_or_above_severity(findings, min_sev)
    if not blocking:
        return None, results, []
    payload = _blocking_payload_dict(results, blocking, min_sev)
    if _prefer_waf_block_html(request):
        blocked: Response = _waf_blocked_html_response(payload)
    else:
        blocked = JSONResponse(status_code=403, content=payload)
    return blocked, results, blocking


@app.get("/__proxy/health")
async def proxy_health() -> dict[str, Any]:
    return {
        "status": "ok",
        "upstream": UPSTREAM_BASE,
        "waf_enabled": _waf_enabled(),
        "waf_block_min_severity": _waf_block_min_severity().value,
        "dashboard_path": f"{WAF_UI_PREFIX}/dashboard",
        "process_started_at": _PROCESS_STARTED_AT,
    }


async def api_dashboard_summary(request: Request | None = None) -> dict[str, Any]:
    up_ok, up_err = await _probe_upstream()
    out = _dashboard_summary_dict(upstream_ok=up_ok, upstream_error=up_err)
    out["process_started_at"] = _PROCESS_STARTED_AT
    out["proxy_rewrite_max_bytes"] = PROXY_REWRITE_MAX_BYTES
    out["env"] = {
        "UPSTREAM_URL": UPSTREAM_RAW,
        "WAF_ENABLED": str(_waf_enabled()).lower(),
        "WAF_BLOCK_MIN_SEVERITY": _waf_block_min_severity().value,
        "WAF_BODY_PREVIEW_MAX": _body_preview_max(),
        "PROXY_REWRITE_MAX_BYTES": PROXY_REWRITE_MAX_BYTES,
    }
    if request is not None:
        out["access"] = _access_snapshot(request)
        out["proxy_public_origin"] = _request_public_origin(request)
    return out


async def dashboard_page(request: Request) -> HTMLResponse:
    initial = await api_dashboard_summary(request)
    tpl = _jinja_env.get_template("dashboard.html")
    html = tpl.render(
        upstream=UPSTREAM_BASE,
        boot=initial,
    )
    return HTMLResponse(
        html,
        headers={
            # 같은 출처에서 업스트림(SPA) SW가 오래된 index를 쓰는 일을 줄임
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
        },
    )


@app.get("/__waf/dashboard")
async def waf_dashboard_canonical(request: Request) -> HTMLResponse:
    return await dashboard_page(request)


@app.get("/__waf/api/summary")
async def waf_api_summary_canonical(request: Request) -> dict[str, Any]:
    return await api_dashboard_summary(request)


@app.get("/__waf/api/traffic")
async def waf_api_traffic() -> dict[str, Any]:
    events = await traffic_log.snapshot_dicts()
    return {"status": "ok", "events": events}


@app.get("/__waf/api/clients")
async def waf_api_clients() -> dict[str, Any]:
    return await traffic_log.clients_snapshot()


def _module_implementation_label(module_id: str) -> str:
    _IMPLEMENTED = {"a05", "a06", "a10"}
    return "rules" if module_id in _IMPLEMENTED else "skeleton"


@app.get("/__waf/api/modules")
async def waf_api_modules() -> dict[str, Any]:
    return {
        "status": "ok",
        "modules": [
            {
                "module_id": m.module_id,
                "owasp_id": m.owasp_id,
                "title": m.title,
                "implementation": _module_implementation_label(m.module_id),
            }
            for m in MODULES
        ],
    }


@app.get("/__waf/api/stats")
async def waf_api_stats() -> dict[str, Any]:
    return await traffic_log.stats_snapshot()


_ALLOWED_UI_BLOCK_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


class BlockSeverityUpdate(BaseModel):
    min_severity: str = Field(..., min_length=2, max_length=16)


@app.put("/__waf/api/settings/block-severity")
async def waf_api_set_block_severity(body: BlockSeverityUpdate) -> dict[str, Any]:
    """런타임에 `WAF_BLOCK_MIN_SEVERITY`와 동일 효과 (프로세스 메모리의 os.environ만 갱신)."""
    key = body.min_severity.strip().lower()
    if key not in _ALLOWED_UI_BLOCK_SEVERITIES:
        raise HTTPException(
            status_code=400,
            detail="min_severity must be one of: low, medium, high, critical",
        )
    os.environ["WAF_BLOCK_MIN_SEVERITY"] = key
    return {
        "status": "ok",
        "waf_block_min_severity": _waf_block_min_severity().value,
    }


# XHR 인터셉터가 리다이렉트하는 차단 페이지 엔드포인트.
# 쿼리파라미터(owasp_id, rule_id, attack_type, severity, location, evidence, category)로
# 탐지 정보를 받아 waf_blocked.html 을 렌더링한다.
@app.get("/__waf/blocked")
async def waf_blocked_redirect_page(request: Request) -> HTMLResponse:
    p = request.query_params
    atk      = p.get("attack_type") or "알 수 없는 공격 유형"
    owasp_id = p.get("owasp_id")    or "—"
    category = p.get("category")    or "—"
    rule_id  = p.get("rule_id")     or "—"
    severity = p.get("severity")    or "high"
    location = p.get("location")    or "—"
    evidence = p.get("evidence")    or "—"
    rows = [{
        "owasp_id":    owasp_id,
        "category":    category,
        "attack_type": atk,
        "rule_id":     rule_id,
        "severity":    severity,
        "location":    location,
        "evidence":    evidence,
    }]
    headline = f"{atk} 취약점이 발견되어 차단되었습니다"
    subline  = f"OWASP {owasp_id} · {category} · 규칙 {rule_id} · 탐지 위치 {location}"
    alert_message = f"[WAF 차단] {headline}\n{subline}"
    tpl  = _jinja_env.get_template("waf_blocked.html")
    html = tpl.render(
        rows=rows,
        boot={"alert_message": alert_message},
        headline=headline,
        subline=subline,
    )
    return HTMLResponse(content=html, status_code=403, headers={"Cache-Control": "no-store"})


# `/__waf/{waf_tail:path}` 보다 먼저 등록해야 정적 파일이 404로 가지 않음
_WAF_STATIC_DIR = _BASE / "static" / "waf"
app.mount(
    "/__waf/static",
    StaticFiles(directory=str(_WAF_STATIC_DIR)),
    name="waf_static",
)


def _waf_unknown_path_response() -> JSONResponse:
    """`/__waf/*` 중 대시보드·요약 API가 아닌 경로 — 업스트림으로 넘기면 Juice Shop HTML이 먹힘."""
    return JSONResponse(
        status_code=404,
        content={"detail": "Unknown WAF UI path; use /__waf/dashboard"},
        headers={"Cache-Control": "no-store"},
    )


@app.api_route("/__waf", methods=METHODS)
@app.api_route("/__waf/", methods=METHODS)
async def waf_prefix_only_reserved(_request: Request) -> JSONResponse:
    return _waf_unknown_path_response()


# catch-all `/{full_path:path}` 보다 먼저 매칭되게 해 `__waf/scripts.js` 등이 업스트림으로 가지 않도록 함
@app.api_route("/__waf/{waf_tail:path}", methods=METHODS)
async def waf_unknown_subpath(waf_tail: str, _request: Request) -> JSONResponse:
    return _waf_unknown_path_response()


@app.get("/api/dashboard/summary")
async def api_dashboard_summary_legacy(request: Request) -> dict[str, Any]:
    return await api_dashboard_summary(request)


@app.get("/dashboard")
async def dashboard_legacy_redirect() -> RedirectResponse:
    return RedirectResponse(url=f"{WAF_UI_PREFIX}/dashboard", status_code=307)


@app.get("/dashboard/")
async def dashboard_legacy_redirect_slash() -> RedirectResponse:
    return RedirectResponse(url=f"{WAF_UI_PREFIX}/dashboard", status_code=307)


@app.api_route("/", methods=METHODS)
async def proxy_root(request: Request) -> Response:
    blocked, scan_results, blocking_findings = await _run_waf_gate(request)
    if blocked is not None:
        rows = tuple(
            _finding_enriched_dict(scan_results, f, evidence_max=400)
            for f in blocking_findings
        )
        await traffic_log.record(
            request, status_code=403, blocked=True, block_findings=rows
        )
        return blocked
    resp = await _forward(request, "")
    await traffic_log.record(request, status_code=resp.status_code, blocked=False)
    return resp


@app.api_route("/{full_path:path}", methods=METHODS)
async def proxy_path(full_path: str, request: Request) -> Response:
    # Reserve /__proxy/*
    if full_path == "__proxy" or full_path.startswith("__proxy/"):
        return Response(status_code=404)
    # catch-all 이 정적 라우트보다 먼저 잡히는 경우 → 업스트림 /dashboard 대신 프록시 UI
    norm = _normalize_proxy_path_segment(full_path)
    if request.method == "GET" and _is_waf_dashboard_path(norm):
        return await dashboard_page(request)
    if request.method == "GET" and _is_waf_summary_api_path(norm):
        return await api_dashboard_summary(request)
    # /__waf/* 는 위의 전용 라우트에서 처리; 여기는 예외 경로만 안전망
    if full_path == "__waf" or full_path.startswith("__waf/"):
        return _waf_unknown_path_response()
    blocked, scan_results, blocking_findings = await _run_waf_gate(request)
    if blocked is not None:
        rows = tuple(
            _finding_enriched_dict(scan_results, f, evidence_max=400)
            for f in blocking_findings
        )
        await traffic_log.record(
            request, status_code=403, blocked=True, block_findings=rows
        )
        return blocked
    resp = await _forward(request, full_path)
    await traffic_log.record(request, status_code=resp.status_code, blocked=False)
    return resp
