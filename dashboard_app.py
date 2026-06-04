"""중앙 대시보드 서버 — 멀티-사이트 WAF 로그 집계 + 로그인 인증.

실행:
    python3 -m uvicorn dashboard_app:app --host 0.0.0.0 --port 8080 --reload
"""

from __future__ import annotations

import io
import json
import math
import os
import shlex
import zipfile
from urllib.parse import quote, unquote_plus, urlparse
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

try:
    from dotenv import load_dotenv

    _BASE = Path(__file__).resolve().parent
    load_dotenv(_BASE / ".env")
except ImportError:
    _BASE = Path(__file__).resolve().parent

import jinja2
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from markupsafe import Markup
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

import auth
import traffic_log
try:
    import site_registry
    _SITE_REGISTRY_AVAILABLE = True
except ImportError:
    _SITE_REGISTRY_AVAILABLE = False
from owasp import MODULES
from request_snapshot import DEFAULT_BODY_PREVIEW_MAX

_TZ_SEOUL = ZoneInfo("Asia/Seoul")
_PROCESS_STARTED_AT = datetime.now(_TZ_SEOUL).strftime("%Y-%m-%d %H:%M:%S")

_WAF_ASSET_VER = (
    os.environ.get("WAF_ASSET_VER", "").strip()
    or _PROCESS_STARTED_AT.replace(" ", "").replace(":", "").replace("-", "")[:12]
)


class StaticNoStoreMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/__waf/static"):
            response.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
            response.headers["Pragma"] = "no-cache"
        return response


# 세션 서명 키 (운영 환경에서는 반드시 변경)
_SECRET_KEY = os.environ.get(
    "WAF_SECRET_KEY", "waf-dashboard-dev-secret-change-in-production"
)

app = FastAPI(
    title="AI Security System — 중앙 대시보드",
    description="멀티-사이트 WAF 트래픽 집계 및 모니터링",
)
app.add_middleware(SessionMiddleware, secret_key=_SECRET_KEY, https_only=False)
app.add_middleware(StaticNoStoreMiddleware)


def _tojson_filter(value: Any) -> Markup:
    """Flask 호환: Jinja2 기본 환경에는 tojson이 없음."""

    def _sanitize_for_boot(obj: Any) -> Any:
        """브라우저 JSON.parse 가 실패하면 대시보드 전체가 비어 보이므로 값 정리."""
        if obj is None or isinstance(obj, (str, bool, int)):
            return obj
        if isinstance(obj, float):
            return obj if math.isfinite(obj) else None
        if isinstance(obj, dict):
            return {str(k): _sanitize_for_boot(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [_sanitize_for_boot(v) for v in obj]
        return str(obj)

    text = json.dumps(
        _sanitize_for_boot(value), ensure_ascii=False, allow_nan=False, default=str
    )
    text = text.replace("</", "<\\/")  # script 태그 조기 종료 방지
    return Markup(text)


_jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(_BASE / "templates")),
    autoescape=jinja2.select_autoescape(["html", "xml"]),
)
_jinja_env.filters["tojson"] = _tojson_filter

_RULES_IMPLEMENTATION_MODULES = frozenset(
    {"a01", "a02", "a03", "a04", "a05", "a06", "a07", "a08", "a09", "a10"}
)


def _module_implementation_label(module_id: str) -> str:
    return "rules" if module_id in _RULES_IMPLEMENTATION_MODULES else "skeleton"


_DASHBOARD_SECTION_META: dict[str, tuple[str, str, str]] = {
    "overview": (
        "대시보드",
        "전체 사이트 WAF 상태 및 차단 KPI",
        "dashboard/partials/overview.html",
    ),
    "preview": (
        "UI Preview",
        "정리된 보안 운영 대시보드 미리보기",
        "dashboard/partials/overview_preview.html",
    ),
    "detections": (
        "탐지·차단 상세",
        "차단된 요청 SQLite 로그",
        "dashboard/partials/detections.html",
    ),
    "traffic": (
        "프록시 로그",
        "통과·차단 전체 트래픽",
        "dashboard/partials/traffic.html",
    ),
    "clients": (
        "접속자",
        "고유 클라이언트 IP·요청 수",
        "dashboard/partials/clients.html",
    ),
    "connect": (
        "사이트 연결",
        "중앙 대시보드와 프록시 연동·설정 받기",
        "dashboard/partials/connect.html",
    ),
    "settings": (
        "저장소·DB 설정",
        "SQLite 경로, 저장 한도, 사용자 관리",
        "dashboard/partials/settings.html",
    ),
    "sql": (
        "SQL 콘솔",
        "읽기 전용 SQLite 쿼리",
        "dashboard/partials/sql_console.html",
    ),
    "sites": (
        "사이트 관리",
        "보호 사이트 등록·정책·예외·IP 관리",
        "dashboard/partials/sites.html",
    ),
}


def _allow_registration() -> bool:
    v = os.environ.get("WAF_ALLOW_REGISTRATION", "true").strip().lower()
    return v not in ("0", "false", "no", "off")


def _registration_public_hint(raw_site_field: str) -> str:
    """회원가입 폼 원문(URL) 한 줄만 site_profiles.public_url 힌트로 저장."""
    if not raw_site_field:
        return ""
    lines = raw_site_field.strip().splitlines()
    line = lines[0].strip() if lines else ""
    line = traffic_log.normalize_upstream_base_url(line)
    if len(line) > 512:
        line = line[:509] + "…"
    return line


def _validated_upstream_url(candidate: str) -> str | None:
    t = traffic_log.normalize_upstream_base_url(candidate)
    if not t:
        return None
    p = urlparse(t)
    if p.scheme not in ("http", "https") or not p.hostname:
        return None
    return t


# ─────────────────────────────────────────────────────────────────────────────
# 인증 헬퍼
# ─────────────────────────────────────────────────────────────────────────────

def _get_user(request: Request) -> dict[str, Any] | None:
    """세션에서 현재 로그인 사용자 dict 반환. 미인증이면 None."""
    return request.session.get("user")


def _effective_site(user: dict[str, Any], requested: str = "") -> str:
    """admin이면 requested_site 그대로, 일반 사용자는 자기 site_id 강제 적용."""
    if user.get("is_admin"):
        return requested
    return str(user.get("site_id") or "")


def _require_page_auth(request: Request) -> dict[str, Any] | RedirectResponse:
    """페이지 라우트용: 미인증이면 RedirectResponse 반환."""
    user = _get_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)
    return user


def _require_api_auth(request: Request) -> dict[str, Any] | JSONResponse:
    """API 라우트용: 미인증이면 401 JSONResponse 반환."""
    user = _get_user(request)
    if user is None:
        return JSONResponse(status_code=401, content={"detail": "로그인이 필요합니다."})
    return user


# ─────────────────────────────────────────────────────────────────────────────
# 앱 시작 이벤트
# ─────────────────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def _startup() -> None:
    auth.ensure_default_users()


# ─────────────────────────────────────────────────────────────────────────────
# 로그인 / 로그아웃
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = "") -> HTMLResponse:
    if _get_user(request):
        return RedirectResponse(url="/__waf/dashboard", status_code=302)
    tpl = _jinja_env.get_template("login.html")
    notice = ""
    tenant_site_id = ""
    if request.query_params.get("registered") == "1":
        notice = "회원가입이 완료되었습니다. 아래에서 로그인하세요."
        tenant_site_id = unquote_plus(request.query_params.get("tenant") or "").strip()
    return HTMLResponse(
        tpl.render(
            error=error,
            notice=notice,
            tenant_site_id=tenant_site_id,
            allow_register=_allow_registration(),
        )
    )


@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
) -> Any:
    user = auth.verify_user(username, password)
    if user is None:
        tpl = _jinja_env.get_template("login.html")
        return HTMLResponse(
            tpl.render(
                error="아이디 또는 비밀번호가 올바르지 않습니다.",
                notice="",
                tenant_site_id="",
                allow_register=_allow_registration(),
            ),
            status_code=401,
        )
    request.session["user"] = user
    if not user.get("is_admin"):
        sid = str(user.get("site_id") or "").strip()
        if not await traffic_log.get_site_install_registered(sid):
            return RedirectResponse(url="/__waf/dashboard/connect", status_code=302)
    return RedirectResponse(url="/__waf/dashboard", status_code=302)


@app.get("/logout")
async def logout(request: Request) -> RedirectResponse:
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, error: str = "") -> HTMLResponse:
    if _get_user(request):
        return RedirectResponse(url="/__waf/dashboard", status_code=302)
    if not _allow_registration():
        raise HTTPException(status_code=404, detail="회원가입이 비활성화되어 있습니다.")
    tpl = _jinja_env.get_template("register.html")
    return HTMLResponse(tpl.render(error=error))


@app.post("/register")
async def register_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    site_id: str = Form(...),
) -> Any:
    if not _allow_registration():
        raise HTTPException(status_code=404, detail="회원가입이 비활성화되어 있습니다.")
    ok, msg, tenant_sid = auth.register_public_user(
        username, password, password_confirm, site_id
    )
    if not ok:
        tpl = _jinja_env.get_template("register.html")
        return HTMLResponse(tpl.render(error=msg), status_code=400)
    if tenant_sid:
        await traffic_log.upsert_registration_site_profile(
            tenant_sid,
            username.strip(),
            _registration_public_hint(site_id),
        )
    q = "?registered=1"
    if tenant_sid:
        q += "&tenant=" + quote(tenant_sid, safe="")
    return RedirectResponse(url="/login" + q, status_code=303)


# ─────────────────────────────────────────────────────────────────────────────
# 대시보드 페이지
# ─────────────────────────────────────────────────────────────────────────────

def _dashboard_env_snapshot() -> dict[str, str]:
    keys = ("TRAFFIC_LOG_DB", "TRAFFIC_LOG_SNAPSHOT_LIMIT", "TRAFFIC_LOG_MAX_ROWS")
    return {k: (os.environ.get(k) or "") for k in keys}


def _central_body_preview_max() -> int:
    raw = os.environ.get("WAF_BODY_PREVIEW_MAX", "").strip()
    if not raw:
        return DEFAULT_BODY_PREVIEW_MAX
    try:
        return max(256, min(int(raw), 1024 * 1024))
    except ValueError:
        return DEFAULT_BODY_PREVIEW_MAX


async def _dashboard_summary(
    request: Request,
    user: dict[str, Any],
    active_site: str = "",
) -> dict[str, Any]:
    site_cards = await traffic_log.sites_manifest()
    sites = [c["site_id"] for c in site_cards]
    stats = await traffic_log.stats_snapshot(site_id=active_site)
    traffic_store = await traffic_log.store_info()
    eff_site = str(active_site or "").strip()
    waf_eff: bool | None
    if eff_site:
        waf_eff = await traffic_log.get_site_waf_enabled(eff_site)
    else:
        waf_eff = None
    out: dict[str, Any] = {
        "status": "ok",
        "summary_scope": "central",
        "sites": sites,
        "site_cards": site_cards,
        "dashboard_stats": stats,
        "traffic_total_logged": int(stats.get("total_logged", 0) or 0),
        "upstream_ok": None,
        "upstream_error": "",
        "waf_enabled": waf_eff,
        "waf_block_min_severity": None,
        "body_preview_max": _central_body_preview_max(),
        "process_started_at": _PROCESS_STARTED_AT,
        "env": _dashboard_env_snapshot(),
        "current_user": user.get("username", ""),
        "is_admin": bool(user.get("is_admin")),
        "user_site_id": user.get("site_id", ""),
        "active_site": active_site,
        "traffic_store": traffic_store,
        "auth_db_path": auth.AUTH_DB_PATH,
    }
    u = request.url
    out["proxy_public_origin"] = f"{u.scheme}://{u.netloc}".rstrip("/")
    return out


async def dashboard_page(
    request: Request,
    user: dict[str, Any],
    section: str = "overview",
) -> HTMLResponse:
    sec = (section or "overview").casefold()
    meta = _DASHBOARD_SECTION_META.get(sec)
    if meta is None:
        raise HTTPException(status_code=404, detail="Unknown dashboard section")
    page_title, page_subtitle, partial_path = meta
    active_site = _effective_site(user, request.query_params.get("site", ""))
    initial = await _dashboard_summary(request, user, active_site)
    sensor_config = auth.get_sensor_config_for_username(user.get("username", "")) or {}
    u = request.url
    central_dashboard_url = f"{u.scheme}://{u.netloc}".rstrip("/")
    upstream_hint_member = ""
    if not user.get("is_admin"):
        upstream_hint_member = await traffic_log.get_site_profile_public_url(
            str(sensor_config.get("site_id") or "")
        )
    member_registered = True
    if not user.get("is_admin"):
        member_registered = await traffic_log.get_site_install_registered(
            str(sensor_config.get("site_id") or "")
        )
    member_needs_install = bool(not user.get("is_admin") and not member_registered)
    if member_needs_install and sec != "connect":
        return RedirectResponse(url="/__waf/dashboard/connect", status_code=302)
    proxy_env_download_local = (
        "/__waf/api/me/proxy-worker-env?upstream="
        + quote("http://127.0.0.1:3000", safe="")
    )
    proxy_env_download_hint = ""
    proxy_zip_download_local = (
        "/__waf/api/me/worker-connect-zip?upstream="
        + quote("http://127.0.0.1:3000", safe="")
    )
    proxy_zip_download_hint = ""
    if upstream_hint_member:
        proxy_env_download_hint = (
            "/__waf/api/me/proxy-worker-env?upstream="
            + quote(upstream_hint_member, safe="")
        )
        proxy_zip_download_hint = (
            "/__waf/api/me/worker-connect-zip?upstream="
            + quote(upstream_hint_member, safe="")
        )
    active_site_kw = active_site.strip()
    conn_site_logged: int | None = None
    if sec == "connect" and active_site_kw:
        st_conn = await traffic_log.stats_snapshot(site_id=active_site_kw)
        conn_site_logged = int(st_conn.get("total_logged", 0) or 0)
    tpl = _jinja_env.get_template("dashboard/layout.html")
    html = tpl.render(
        upstream="",
        page_title=page_title,
        page_subtitle=page_subtitle,
        active_section=sec,
        partial_path=partial_path,
        boot=initial,
        current_user=user.get("username", ""),
        is_admin=bool(user.get("is_admin")),
        user_site_id=user.get("site_id", ""),
        sensor_site_id=sensor_config.get("site_id", ""),
        sensor_token=sensor_config.get("sensor_token", ""),
        central_dashboard_url=central_dashboard_url,
        upstream_hint_member=upstream_hint_member,
        proxy_env_download_local=proxy_env_download_local,
        proxy_env_download_hint=proxy_env_download_hint,
        proxy_zip_download_local=proxy_zip_download_local,
        proxy_zip_download_hint=proxy_zip_download_hint,
        connect_site_logged=conn_site_logged,
        connect_effective_site=active_site_kw,
        member_needs_install=member_needs_install,
        waf_asset_ver=_WAF_ASSET_VER,
    )
    return HTMLResponse(
        html,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
        },
    )


@app.get("/")
async def root_redirect(request: Request) -> RedirectResponse:
    if _get_user(request):
        return RedirectResponse(url="/__waf/dashboard", status_code=302)
    return RedirectResponse(url="/login", status_code=302)


@app.get("/__waf/dashboard")
async def waf_dashboard_canonical(request: Request) -> Any:
    """로그인 후 기본 화면: 개요(사이드바 「개요」와 같은 섹션)."""
    result = _require_page_auth(request)
    if isinstance(result, RedirectResponse):
        return result
    return await dashboard_page(request, result, "overview")


@app.get("/__waf/dashboard-preview")
async def waf_dashboard_preview(request: Request) -> Any:
    result = _require_page_auth(request)
    if isinstance(result, RedirectResponse):
        return result
    return await dashboard_page(request, result, "preview")


@app.get("/__waf/dashboard/{section}")
async def waf_dashboard_section_route(request: Request, section: str) -> Any:
    result = _require_page_auth(request)
    if isinstance(result, RedirectResponse):
        return result
    return await dashboard_page(request, result, section)


# ─────────────────────────────────────────────────────────────────────────────
# API 엔드포인트
# ─────────────────────────────────────────────────────────────────────────────


async def _member_worker_env_plaintext(
    request: Request,
    result: dict[str, Any],
    upstream: str,
) -> tuple[str, str]:
    """일반 회원용 waf-worker.env 본문과 확정된 UPSTREAM_URL."""
    if result.get("is_admin"):
        raise HTTPException(
            status_code=400,
            detail="일반 회원 계정으로 로그인 후 저장하거나, scripts/print_proxy_env_for_user.py 로 생성하세요.",
        )
    uname = str(result.get("username") or "").strip()
    cfg = auth.get_sensor_config_for_username(uname)
    if not cfg:
        raise HTTPException(status_code=404, detail="센서 정보를 찾지 못했습니다.")
    sid = str(cfg.get("site_id") or "").strip()
    tok = str(cfg.get("sensor_token") or "").strip()
    if not sid or not tok:
        raise HTTPException(status_code=400, detail="SITE_ID 또는 SENSOR_TOKEN 이 비어 있습니다.")

    eff = _validated_upstream_url(upstream)
    if eff is None:
        hint = await traffic_log.get_site_profile_public_url(sid)
        eff = _validated_upstream_url(hint)
    eff_upstream = eff or "http://127.0.0.1:3000"

    u = request.url
    central = f"{u.scheme}://{u.netloc}".rstrip("/")
    body = "\n".join(
        [
            f"CENTRAL_DASHBOARD_URL={central}",
            f"SENSOR_TOKEN={tok}",
            f"SITE_ID={sid}",
            f"UPSTREAM_URL={eff_upstream}",
            "",
            "# 이 파일 저장: 프로젝트 폴더에 .env 이름으로 저장 (대시보드 「사이트 연결」에서 받음)",
            "# 실행: 팀 안내 방법 — Docker Desktop, 맥 .command 더블클릭 등 (터미널 없이 받은 스크립트만으로도 가능)",
            "# 테스트 URL: 업스트림(주스 직링)이 아니라 «프록시» 주소(예: http://<PC LAN IP>:8081/) 로 접속",
        ]
    )
    return body, eff_upstream


@app.get("/__waf/api/summary")
async def waf_api_summary(request: Request) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    active_site = _effective_site(result, request.query_params.get("site", ""))
    return await _dashboard_summary(request, result, active_site)


@app.get("/__waf/api/me/proxy-worker-env")
async def waf_proxy_worker_env_attachment(request: Request, upstream: str = "") -> Any:
    """로그인 멤버가 프록시용 .env 를 내려받도록 (복붙량 감소)."""
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    body, _ = await _member_worker_env_plaintext(request, result, upstream)
    return Response(
        content=body,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="waf-worker.env"',
            "Cache-Control": "no-store",
        },
    )


@app.get("/__waf/api/me/worker-connect-zip")
async def waf_worker_connect_zip(request: Request, upstream: str = "") -> Any:
    """설정 파일 + 짧은 안내를 한 ZIP으로 내려 한 단계로 연결 준비."""
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    body, eff_upstream = await _member_worker_env_plaintext(request, result, upstream)
    readme = (
        "WAF 워커 연결 패키지\n"
        "============================\n\n"
        "이 ZIP 안의 waf-worker.env 를 팀 안내 위치에 두세요 "
        "(보통 프로젝트 루트에 .env 로 저장).\n\n"
        "그다음 워커(프록시)를 실행하세요. "
        "(Docker · Start-*.command · make 등 팀에서 정한 방법.)\n\n"
        "브라우저로 테스트할 때는 업스트림 앱 포트가 아니라 "
        "«프록시» 주소로 접속해야 이 대시보드에 로그가 쌓입니다.\n\n"
        "이 패키지를 받을 때 사용한 UPSTREAM_URL:\n"
        f"  {eff_upstream}\n\n"
        "문제 시 대시보드 「사이트 연결」에서 패키지를 다시 받을 수 있습니다.\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("waf-worker.env", body)
        zf.writestr("연결안내.txt", readme)
    payload = buf.getvalue()
    return Response(
        content=payload,
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="waf-worker-connect.zip"',
            "Cache-Control": "no-store",
        },
    )


def _shell_export_lines(env_body: str) -> str:
    lines: list[str] = []
    for raw in env_body.splitlines():
        if not raw or raw.lstrip().startswith("#") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        lines.append(f"export {key}={shlex.quote(value)}")
    return "\n".join(lines)


def _powershell_env_lines(env_body: str) -> str:
    lines: list[str] = []
    for raw in env_body.splitlines():
        if not raw or raw.lstrip().startswith("#") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        escaped = value.replace("'", "''")
        lines.append(f"$env:{key} = '{escaped}'")
    return "\n".join(lines)


def _installer_script(
    target_os: str,
    env_body: str,
    eff_upstream: str,
) -> tuple[str, str, str]:
    """OS별 더블클릭/실행용 워커 설치 스크립트."""
    project_root = str(_BASE)
    shell_project_root = shlex.quote(project_root)
    ps_project_root = project_root.replace("'", "''")
    if target_os == "macos":
        content = f"""#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
if [[ ! -f "main.py" || ! -f "requirements.txt" ]]; then
  if [[ -f {shell_project_root}/main.py && -f {shell_project_root}/requirements.txt ]]; then
    ROOT={shell_project_root}
    cd "$ROOT"
  else
  echo "이 설치 파일은 AI Security Agent 프로젝트 폴더 안에 두고 실행해야 합니다."
  echo "현재 폴더: $ROOT"
  read -r -p "Enter 키를 누르면 종료합니다..."
  exit 1
  fi
fi
cat > .env <<'EOF'
{env_body}
EOF
if [[ ! -d "system" ]]; then
  python3 -m venv system
fi
source system/bin/activate
python -m pip install -U pip
python -m pip install -r requirements.txt
{_shell_export_lines(env_body)}
export LISTEN_PORT="${{LISTEN_PORT:-8081}}"
echo ""
echo "원본 사이트: {eff_upstream}"
echo "WAF 보호 주소: http://127.0.0.1:${{LISTEN_PORT}}"
echo "대시보드 로그 연결: $CENTRAL_DASHBOARD_URL"
echo ""
exec python -m uvicorn main:app --host 0.0.0.0 --port "$LISTEN_PORT" --reload
"""
        return "install-waf-macos.command", "application/octet-stream", content
    if target_os == "linux":
        content = f"""#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
if [[ ! -f "main.py" || ! -f "requirements.txt" ]]; then
  if [[ -f {shell_project_root}/main.py && -f {shell_project_root}/requirements.txt ]]; then
    ROOT={shell_project_root}
    cd "$ROOT"
  else
  echo "이 설치 파일은 AI Security Agent 프로젝트 폴더 안에 두고 실행해야 합니다."
  echo "현재 폴더: $ROOT"
  exit 1
  fi
fi
cat > .env <<'EOF'
{env_body}
EOF
if [[ ! -d "system" ]]; then
  python3 -m venv system
fi
source system/bin/activate
python -m pip install -U pip
python -m pip install -r requirements.txt
{_shell_export_lines(env_body)}
export LISTEN_PORT="${{LISTEN_PORT:-8081}}"
echo "원본 사이트: {eff_upstream}"
echo "WAF 보호 주소: http://127.0.0.1:${{LISTEN_PORT}}"
echo "대시보드 로그 연결: $CENTRAL_DASHBOARD_URL"
exec python -m uvicorn main:app --host 0.0.0.0 --port "$LISTEN_PORT" --reload
"""
        return "install-waf-linux.sh", "text/x-shellscript; charset=utf-8", content
    if target_os == "windows":
        content = f"""$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
if (!(Test-Path "main.py") -or !(Test-Path "requirements.txt")) {{
  $ServerProjectRoot = '{ps_project_root}'
  if ((Test-Path (Join-Path $ServerProjectRoot "main.py")) -and (Test-Path (Join-Path $ServerProjectRoot "requirements.txt"))) {{
    $Root = $ServerProjectRoot
    Set-Location $Root
  }} else {{
  Write-Host "이 설치 파일은 AI Security Agent 프로젝트 폴더 안에 두고 실행해야 합니다."
  Write-Host "현재 폴더: $Root"
  Read-Host "Enter 키를 누르면 종료합니다"
  exit 1
  }}
}}
@'
{env_body}
'@ | Set-Content -Path ".env" -Encoding UTF8
if (!(Test-Path "system")) {{
  py -3 -m venv system
}}
& ".\\system\\Scripts\\python.exe" -m pip install -U pip
& ".\\system\\Scripts\\python.exe" -m pip install -r requirements.txt
{_powershell_env_lines(env_body)}
if (!$env:LISTEN_PORT) {{ $env:LISTEN_PORT = "8081" }}
Write-Host ""
Write-Host "원본 사이트: {eff_upstream}"
Write-Host "WAF 보호 주소: http://127.0.0.1:$env:LISTEN_PORT"
Write-Host "대시보드 로그 연결: $env:CENTRAL_DASHBOARD_URL"
Write-Host ""
& ".\\system\\Scripts\\python.exe" -m uvicorn main:app --host 0.0.0.0 --port $env:LISTEN_PORT --reload
"""
        return "install-waf-windows.ps1", "text/plain; charset=utf-8", content
    raise HTTPException(status_code=404, detail="지원하지 않는 운영체제입니다.")


@app.get("/__waf/api/me/install/{target_os}")
async def waf_worker_installer(request: Request, target_os: str, upstream: str = "") -> Any:
    """사이트 연결 화면의 OS별 설치 버튼에서 내려받는 실행 스크립트."""
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    env_body, eff_upstream = await _member_worker_env_plaintext(request, result, upstream)
    sid = str(result.get("site_id") or "").strip()
    uname = str(result.get("username") or "").strip()
    if sid and not result.get("is_admin"):
        await traffic_log.upsert_registration_site_profile(
            sid, uname, eff_upstream[:512], install_registered=True
        )
    filename, media_type, content = _installer_script(target_os, env_body, eff_upstream)
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


class MemberPublicUrlHintIn(BaseModel):
    public_url: str = Field(default="", max_length=520)


@app.put("/__waf/api/me/public-url-hint")
async def waf_put_member_public_url_hint(
    request: Request, body: MemberPublicUrlHintIn
) -> Any:
    """일반 회원이 붙여넣은 업스트림(브라우저 주소)을 정규화해 site_profiles.public_url 에 남김."""
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    sid_raw = str(result.get("site_id") or "").strip()
    sid = auth.normalize_site_id(sid_raw)
    if not sid:
        raise HTTPException(
            status_code=400,
            detail="site_id 가 없습니다. 관리자에게 계정 할당을 확인하세요.",
        )
    norm = traffic_log.normalize_upstream_base_url(body.public_url)
    valid = _validated_upstream_url(norm)
    if valid is None:
        raise HTTPException(
            status_code=400,
            detail="http:// 또는 https:// 로 시작하는 올바른 주소여야 합니다.",
        )
    uname = str(result.get("username") or "").strip()
    await traffic_log.upsert_registration_site_profile(
        sid, uname, valid[:512], install_registered=True
    )
    return {"status": "ok", "public_url": valid, "install_registered": True}


@app.get("/api/dashboard/summary")
async def legacy_dashboard_summary_json(request: Request) -> Any:
    """프록시 단독 서버 시절 호환 경로 (README 구버전 링크 등)."""
    return await waf_api_summary(request)


@app.get("/dashboard")
@app.get("/dashboard/")
async def legacy_dashboard_html_path(request: Request) -> Any:
    result = _require_page_auth(request)
    if isinstance(result, RedirectResponse):
        return result
    return RedirectResponse(url="/__waf/dashboard", status_code=307)


@app.get("/__waf/api/sites")
async def waf_api_sites(request: Request) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    site_cards = await traffic_log.sites_manifest()
    if not result.get("is_admin"):
        own = str(result.get("site_id") or "")
        site_cards = [c for c in site_cards if c.get("site_id") == own]
    sites = [c["site_id"] for c in site_cards]
    return {"status": "ok", "sites": sites, "site_cards": site_cards}


@app.get("/__waf/api/traffic")
async def waf_api_traffic(request: Request, site: str = "") -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    effective = _effective_site(result, site)
    events = await traffic_log.snapshot_dicts(site_id=effective)
    return {"status": "ok", "events": events}


@app.delete("/__waf/api/traffic/{event_id}")
async def waf_api_delete_traffic(request: Request, event_id: int) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    ok = await traffic_log.delete_by_id(event_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Event not found")
    return {"status": "ok", "deleted": event_id}


@app.post("/__waf/api/traffic/reset")
async def waf_api_reset_traffic(request: Request) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    # 관리자만 전체 삭제, 일반 사용자는 자기 사이트만 삭제
    if result.get("is_admin"):
        await traffic_log.clear_all_async()
    else:
        await traffic_log.clear_by_site_async(result.get("site_id", ""))
    return {"status": "ok", "cleared": True}


@app.get("/__waf/api/clients")
async def waf_api_clients(request: Request, site: str = "") -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    effective = _effective_site(result, site)
    return await traffic_log.clients_snapshot(site_id=effective)


@app.get("/__waf/api/modules")
async def waf_api_modules(request: Request) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
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
async def waf_api_stats(request: Request, site: str = "") -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    effective = _effective_site(result, site)
    return await traffic_log.stats_snapshot(site_id=effective)


class SqlConsoleQueryIn(BaseModel):
    sql: str = Field(default="", max_length=50_000)


class SensorIngestEvent(BaseModel):
    site_id: str = Field(..., min_length=1, max_length=128)
    sensor_token: str | None = Field(default=None, max_length=512)
    time_iso: str | None = Field(default=None, max_length=64)
    client_ip: str = Field(default="—", max_length=128)
    method: str = Field(default="GET", max_length=16)
    path: str = Field(default="/", max_length=2048)
    user_agent: str = Field(default="—", max_length=512)
    status_code: int = 0
    blocked: bool = False
    block_findings: list[dict[str, Any]] = Field(default_factory=list)
    sensor_label: str | None = Field(default=None, max_length=140)
    sensor_public_origin: str | None = Field(default=None, max_length=520)


@app.post("/__waf/api/ingest")
async def waf_api_ingest(request: Request, body: SensorIngestEvent) -> Any:
    token = (request.headers.get("x-sensor-token") or body.sensor_token or "").strip()
    site_id = auth.normalize_site_id(body.site_id)
    if not auth.verify_sensor_token(site_id, token):
        raise HTTPException(status_code=403, detail="센서 토큰이 올바르지 않습니다.")
    event = (
        body.model_dump(exclude_none=True)
        if hasattr(body, "model_dump")
        else body.dict(exclude_none=True)
    )
    event["site_id"] = site_id
    event.pop("sensor_token", None)
    await traffic_log.record_event_dict(event)
    return {"status": "ok", "site_id": site_id}


@app.get("/__waf/api/sensor/site-waf")
async def waf_api_sensor_site_waf(request: Request, site: str = "") -> Any:
    """워커(main.py)가 사이트별 WAF 차단 활성 여부를 읽습니다 (세션 불필요, 센서 토큰)."""
    token = (request.headers.get("x-sensor-token") or "").strip()
    sid = auth.normalize_site_id(site)
    if not sid or not auth.verify_sensor_token(sid, token):
        raise HTTPException(status_code=403, detail="센서 토큰이 올바르지 않습니다.")
    enabled = await traffic_log.get_site_waf_enabled(sid)
    return {"status": "ok", "site_id": sid, "waf_enabled": enabled}


class WafSiteToggleIn(BaseModel):
    enabled: bool
    site_id: str = Field(default="", max_length=128)


@app.post("/__waf/api/settings/waf-enabled")
async def waf_api_post_site_waf_enabled(request: Request, body: WafSiteToggleIn) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    if result.get("is_admin"):
        sid = auth.normalize_site_id(body.site_id)
        if not sid:
            raise HTTPException(
                status_code=400,
                detail="사이트 필터에서 사이트를 선택한 뒤 WAF를 전환합니다.",
            )
    else:
        sid = auth.normalize_site_id(str(result.get("site_id") or ""))
        if not sid:
            raise HTTPException(
                status_code=400, detail="이 계정에 연결된 사이트 ID가 없습니다.",
            )
    await traffic_log.set_site_waf_enabled(sid, bool(body.enabled))
    return {"status": "ok", "site_id": sid, "waf_enabled": bool(body.enabled)}


@app.get("/__waf/api/sql-console/schema")
async def waf_sql_console_schema(request: Request) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    return await traffic_log.schema_snapshot()


@app.post("/__waf/api/sql-console/query")
async def waf_sql_console_query(request: Request, body: SqlConsoleQueryIn) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    try:
        return await traffic_log.run_console_query(body.sql)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/__waf/api/settings/traffic-store")
async def waf_api_get_store_info(request: Request) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    return await traffic_log.store_info()


class TrafficStoreUpdate(BaseModel):
    snapshot_limit: int | None = None
    max_stored_rows: int | None = None
    traffic_log_db: str | None = None


@app.put("/__waf/api/settings/traffic-store")
async def waf_api_put_store_info(request: Request, body: TrafficStoreUpdate) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    if not result.get("is_admin"):
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다.")
    if body.snapshot_limit is not None:
        os.environ["TRAFFIC_LOG_SNAPSHOT_LIMIT"] = str(max(1, min(int(body.snapshot_limit), 50_000)))
    if body.max_stored_rows is not None:
        os.environ["TRAFFIC_LOG_MAX_ROWS"] = str(max(0, min(int(body.max_stored_rows), 500_000)))
    if body.traffic_log_db is not None:
        try:
            await traffic_log.reopen_database_async(body.traffic_log_db)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return await traffic_log.store_info()


# ─────────────────────────────────────────────────────────────────────────────
# 사용자 관리 API (admin 전용)
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/__waf/api/users")
async def waf_api_get_users(request: Request) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    if not result.get("is_admin"):
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다.")
    return {"status": "ok", "users": auth.get_all_users()}


class CreateUserIn(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)
    site_id: str = Field(default="", max_length=64)
    is_admin: bool = False


@app.post("/__waf/api/users")
async def waf_api_create_user(request: Request, body: CreateUserIn) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    if not result.get("is_admin"):
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다.")
    ok = auth.create_user(
        body.username, body.password, site_id=body.site_id, is_admin=body.is_admin
    )
    if not ok:
        raise HTTPException(status_code=409, detail=f"이미 존재하는 사용자명입니다: {body.username}")
    if body.site_id.strip() and not body.is_admin:
        await traffic_log.upsert_registration_site_profile(
            body.site_id.strip(),
            body.username.strip(),
            "",
        )
    return {"status": "ok", "username": body.username}


@app.delete("/__waf/api/users/{username}")
async def waf_api_delete_user(request: Request, username: str) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    if not result.get("is_admin"):
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다.")
    if username == result.get("username"):
        raise HTTPException(status_code=400, detail="자기 자신은 삭제할 수 없습니다.")
    ok = auth.delete_user(username)
    if not ok:
        raise HTTPException(status_code=404, detail=f"사용자를 찾을 수 없습니다: {username}")
    return {"status": "ok", "deleted": username}


# ─────────────────────────────────────────────────────────────────────────────
# 사이트 관리 API (site_registry)
# ─────────────────────────────────────────────────────────────────────────────

class _SiteCreateBody(BaseModel):
    display_name: str = Field(default="", max_length=128)
    domain: str = Field(..., min_length=1, max_length=256)
    origin_url: str = Field(..., min_length=1, max_length=512)
    mode: str = Field(default="block")
    min_severity: str = Field(default="high")


class _SiteUpdateBody(BaseModel):
    display_name: str | None = Field(default=None, max_length=128)
    origin_url: str | None = Field(default=None, max_length=512)
    status: str | None = Field(default=None)
    mode: str | None = Field(default=None)
    min_severity: str | None = Field(default=None)
    ai_enabled: bool | None = Field(default=None)
    fail_mode: str | None = Field(default=None)


class _ExceptionBody(BaseModel):
    path_pattern: str = Field(..., min_length=1, max_length=256)
    rule_id: str = Field(default="", max_length=64)
    method: str = Field(default="", max_length=10)
    reason: str = Field(default="", max_length=256)


class _IpPolicyBody(BaseModel):
    ip_cidr: str = Field(..., min_length=1, max_length=64)
    action: str = Field(default="block")
    reason: str = Field(default="", max_length=256)


def _client_ip_dash(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return (request.client.host if request.client else "") or ""


@app.get("/__waf/api/sites")
async def api_list_sites(request: Request) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    if not _SITE_REGISTRY_AVAILABLE:
        return JSONResponse(status_code=503, content={"detail": "site_registry 모듈을 불러올 수 없습니다."})
    owner = None if result.get("is_admin") else result.get("username")
    sites = site_registry.list_sites(owner_username=owner)
    # 각 사이트에 통계 추가
    for s in sites:
        try:
            stats = site_registry.get_site_stats(s["site_id"], hours=24)
            s["stats_24h"] = stats
        except Exception:
            s["stats_24h"] = {}
    return {"sites": sites, "count": len(sites)}


@app.post("/__waf/api/sites")
async def api_create_site(request: Request, body: _SiteCreateBody) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    if not _SITE_REGISTRY_AVAILABLE:
        return JSONResponse(status_code=503, content={"detail": "site_registry 모듈을 불러올 수 없습니다."})
    owner = result.get("username", "admin")
    try:
        info = site_registry.create_site(
            display_name=body.display_name or body.domain,
            domain=body.domain,
            origin_url=body.origin_url,
            owner_username=owner,
            mode=body.mode,
            min_severity=body.min_severity,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    site_registry.add_audit_log(
        username=owner, site_id=info["site_id"], action="create_site",
        after=info, client_ip=_client_ip_dash(request),
    )
    return {"status": "ok", **info}


@app.get("/__waf/api/sites/{site_id}")
async def api_get_site(request: Request, site_id: str) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    if not _SITE_REGISTRY_AVAILABLE:
        return JSONResponse(status_code=503, content={"detail": "site_registry 모듈을 불러올 수 없습니다."})
    if not result.get("is_admin") and result.get("username") != site_id:
        # 일반 사용자는 자기 사이트만
        owned = [s["site_id"] for s in site_registry.list_sites(owner_username=result.get("username"))]
        if site_id not in owned:
            raise HTTPException(status_code=403, detail="이 사이트에 대한 권한이 없습니다.")
    site = site_registry.get_site(site_id)
    if site is None:
        raise HTTPException(status_code=404, detail="사이트를 찾을 수 없습니다.")
    site["exceptions"] = site_registry.list_exceptions(site_id)
    site["ip_policies"] = site_registry.list_ip_policies(site_id)
    site["stats_24h"] = site_registry.get_site_stats(site_id)
    return site


@app.put("/__waf/api/sites/{site_id}")
async def api_update_site(request: Request, site_id: str, body: _SiteUpdateBody) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    if not _SITE_REGISTRY_AVAILABLE:
        return JSONResponse(status_code=503, content={"detail": "site_registry 모듈을 불러올 수 없습니다."})
    if not result.get("is_admin"):
        owned = [s["site_id"] for s in site_registry.list_sites(owner_username=result.get("username"))]
        if site_id not in owned:
            raise HTTPException(status_code=403, detail="이 사이트에 대한 권한이 없습니다.")
    before = site_registry.get_site(site_id)
    if before is None:
        raise HTTPException(status_code=404, detail="사이트를 찾을 수 없습니다.")
    try:
        site_registry.update_site(
            site_id,
            display_name=body.display_name,
            origin_url=body.origin_url,
            status=body.status,
            mode=body.mode,
            min_severity=body.min_severity,
            ai_enabled=body.ai_enabled,
            fail_mode=body.fail_mode,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    after = site_registry.get_site(site_id)
    site_registry.add_audit_log(
        username=result.get("username", ""), site_id=site_id, action="update_site",
        before=before, after=after, client_ip=_client_ip_dash(request),
    )
    return {"status": "ok", "site_id": site_id}


@app.delete("/__waf/api/sites/{site_id}")
async def api_delete_site(request: Request, site_id: str) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    if not result.get("is_admin"):
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다.")
    if not _SITE_REGISTRY_AVAILABLE:
        return JSONResponse(status_code=503, content={"detail": "site_registry 모듈을 불러올 수 없습니다."})
    before = site_registry.get_site(site_id)
    if before is None:
        raise HTTPException(status_code=404, detail="사이트를 찾을 수 없습니다.")
    site_registry.delete_site(site_id)
    site_registry.add_audit_log(
        username=result.get("username", ""), site_id=site_id, action="delete_site",
        before=before, client_ip=_client_ip_dash(request),
    )
    return {"status": "ok", "deleted": site_id}


# ── 예외 경로 ──

@app.get("/__waf/api/sites/{site_id}/exceptions")
async def api_list_exceptions(request: Request, site_id: str) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    if not _SITE_REGISTRY_AVAILABLE:
        return JSONResponse(status_code=503, content={"detail": "site_registry 모듈을 불러올 수 없습니다."})
    return {"exceptions": site_registry.list_exceptions(site_id)}


@app.post("/__waf/api/sites/{site_id}/exceptions")
async def api_add_exception(request: Request, site_id: str, body: _ExceptionBody) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    if not _SITE_REGISTRY_AVAILABLE:
        return JSONResponse(status_code=503, content={"detail": "site_registry 모듈을 불러올 수 없습니다."})
    eid = site_registry.add_exception(
        site_id, body.path_pattern,
        rule_id=body.rule_id, method=body.method,
        reason=body.reason, created_by=result.get("username", ""),
    )
    site_registry.add_audit_log(
        username=result.get("username", ""), site_id=site_id, action="add_exception",
        after={"path_pattern": body.path_pattern, "rule_id": body.rule_id},
        client_ip=_client_ip_dash(request),
    )
    return {"status": "ok", "id": eid}


@app.delete("/__waf/api/sites/{site_id}/exceptions/{exc_id}")
async def api_delete_exception(request: Request, site_id: str, exc_id: int) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    if not _SITE_REGISTRY_AVAILABLE:
        return JSONResponse(status_code=503, content={"detail": "site_registry 모듈을 불러올 수 없습니다."})
    site_registry.delete_exception(exc_id)
    return {"status": "ok", "deleted": exc_id}


# ── IP 정책 ──

@app.get("/__waf/api/sites/{site_id}/ip-policies")
async def api_list_ip_policies(request: Request, site_id: str) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    if not _SITE_REGISTRY_AVAILABLE:
        return JSONResponse(status_code=503, content={"detail": "site_registry 모듈을 불러올 수 없습니다."})
    return {"ip_policies": site_registry.list_ip_policies(site_id)}


@app.post("/__waf/api/sites/{site_id}/ip-policies")
async def api_add_ip_policy(request: Request, site_id: str, body: _IpPolicyBody) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    if not _SITE_REGISTRY_AVAILABLE:
        return JSONResponse(status_code=503, content={"detail": "site_registry 모듈을 불러올 수 없습니다."})
    try:
        pid = site_registry.add_ip_policy(site_id, body.ip_cidr, body.action, body.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    site_registry.add_audit_log(
        username=result.get("username", ""), site_id=site_id, action="add_ip_policy",
        after={"ip_cidr": body.ip_cidr, "action": body.action},
        client_ip=_client_ip_dash(request),
    )
    return {"status": "ok", "id": pid}


@app.delete("/__waf/api/sites/{site_id}/ip-policies/{policy_id}")
async def api_delete_ip_policy(request: Request, site_id: str, policy_id: int) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    if not _SITE_REGISTRY_AVAILABLE:
        return JSONResponse(status_code=503, content={"detail": "site_registry 모듈을 불러올 수 없습니다."})
    site_registry.delete_ip_policy(policy_id)
    return {"status": "ok", "deleted": policy_id}


# ── 감사 로그 ──

@app.get("/__waf/api/sites/{site_id}/audit-logs")
async def api_audit_logs(request: Request, site_id: str) -> Any:
    result = _require_api_auth(request)
    if isinstance(result, JSONResponse):
        return result
    if not result.get("is_admin"):
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다.")
    if not _SITE_REGISTRY_AVAILABLE:
        return JSONResponse(status_code=503, content={"detail": "site_registry 모듈을 불러올 수 없습니다."})
    logs = site_registry.list_audit_logs(site_id=site_id, limit=200)
    return {"logs": logs}




# ── Caddy On-demand TLS 검증 엔드포인트 ──────────────────────────────────────
# Caddy가 cert 발급 전 이 엔드포인트에 GET 요청을 보냄:
#   GET /__waf/api/tls-check?domain=<도메인>
# WAF에 등록된 도메인이면 200 OK, 미등록이면 403 Forbidden.
# 이를 통해 무관한 도메인의 Let's Encrypt 발급 시도를 차단함.

@app.get("/__waf/api/tls-check", include_in_schema=False)
async def _tls_domain_check(domain: str = "") -> Response:
    """Caddy on-demand TLS 도메인 소유권 확인 (인증 없음 — Caddy 내부 호출 전용)."""
    if not domain:
        return Response(status_code=400, content="domain parameter required")

    if not _SITE_REGISTRY_AVAILABLE:
        # site_registry 없을 때: 환경변수 UPSTREAM_URL 이 있으면 싱글사이트 모드
        # 도메인 체크 불가 -> 일단 허용 (운영에서는 site_registry 필수)
        return Response(status_code=200, content="ok")

    # domain 정규화 (포트 제거, 소문자)
    clean = domain.split(":")[0].strip().lower()
    if not clean:
        return Response(status_code=400, content="invalid domain")

    route = site_registry.lookup_route(clean)
    if route is None:
        # 미등록 도메인: cert 발급 거부
        return Response(status_code=403, content="domain not registered")

    return Response(status_code=200, content="ok")

# ── site_registry 초기화 ──

@app.on_event("startup")
async def _init_site_registry() -> None:
    if _SITE_REGISTRY_AVAILABLE:
        try:
            site_registry.init()
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("site_registry init failed: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# 정적 파일
# ─────────────────────────────────────────────────────────────────────────────

_WAF_STATIC_DIR = _BASE / "static" / "waf"
app.mount(
    "/__waf/static",
    StaticFiles(directory=str(_WAF_STATIC_DIR)),
    name="waf_static",
)
