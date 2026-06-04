"""프록시 워커(main) 전용 로컬 트래픽 로그 뷰어.

Juice Shop 등 업스트림이 `/login` 을 쓰므로, 인증·UI 경로만 `/__waf/worker/*` 로 분리한다.
계정은 `auth` / `waf_auth.sqlite3` 과 동일(admin 등).
"""

from __future__ import annotations

import os
from typing import Any

import auth
import jinja2
import traffic_log
from ai_second_pass import ai_second_pass_status
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse


def attach_worker_console(app: Any, jinja_env: jinja2.Environment) -> None:
    site_id = os.environ.get("SITE_ID", "default")

    router = APIRouter(prefix="/__waf/worker", tags=["proxy-worker-console"])

    def _require_admin_html(request: Request) -> dict[str, Any] | RedirectResponse:
        user = request.session.get("user")
        if user is None or not user.get("is_admin"):
            return RedirectResponse(url="/__waf/worker/login", status_code=302)
        return user

    def _require_admin_api(request: Request) -> dict[str, Any] | JSONResponse:
        u = request.session.get("user")
        if u is None or not u.get("is_admin"):
            return JSONResponse(
                status_code=401,
                content={"detail": "관리자 로그인이 필요합니다."},
            )
        return u

    @router.get("/login", response_class=HTMLResponse, response_model=None)
    async def worker_login_page(request: Request) -> HTMLResponse | RedirectResponse:
        cur = request.session.get("user")
        if isinstance(cur, dict) and cur.get("is_admin"):
            return RedirectResponse(url="/__waf/worker/logs", status_code=302)
        err = ""
        if request.query_params.get("error") == "forbidden":
            err = "관리자 계정만 접근할 수 있습니다."
        tpl = jinja_env.get_template("worker_login.html")
        return HTMLResponse(
            tpl.render(error=err, site_id=site_id),
            headers={"Cache-Control": "no-store"},
        )

    @router.post("/login", response_model=None)
    async def worker_login_submit(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
    ) -> Any:
        user = auth.verify_user(username, password)
        if user is None or not user.get("is_admin"):
            tpl = jinja_env.get_template("worker_login.html")
            return HTMLResponse(
                tpl.render(
                    error="관리자 아이디·비밀번호를 확인하세요.",
                    site_id=site_id,
                ),
                status_code=401,
            )
        request.session["user"] = user
        return RedirectResponse(url="/__waf/worker/logs", status_code=302)

    @router.get("/logout", response_model=None)
    async def worker_logout(request: Request) -> RedirectResponse:
        request.session.pop("user", None)
        return RedirectResponse(url="/__waf/worker/login", status_code=302)

    @router.get("", include_in_schema=False, response_model=None)
    @router.get("/", include_in_schema=False, response_model=None)
    async def worker_root(request: Request) -> RedirectResponse:
        cur = request.session.get("user")
        if isinstance(cur, dict) and cur.get("is_admin"):
            return RedirectResponse(url="/__waf/worker/logs", status_code=302)
        return RedirectResponse(url="/__waf/worker/login", status_code=302)

    @router.get("/logs", response_class=HTMLResponse, response_model=None)
    async def worker_logs_page(request: Request) -> HTMLResponse | RedirectResponse:
        gate = _require_admin_html(request)
        if isinstance(gate, RedirectResponse):
            return gate
        events = await traffic_log.snapshot_dicts(site_id=site_id)
        tpl = jinja_env.get_template("worker_logs.html")
        html = tpl.render(
            events=events,
            site_id=site_id,
            ai_second_pass=ai_second_pass_status(),
        )
        return HTMLResponse(
            html,
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate",
                "Pragma": "no-cache",
            },
        )

    @router.get("/api/traffic", response_model=None)
    async def worker_api_traffic(request: Request) -> Any:
        gate = _require_admin_api(request)
        if isinstance(gate, JSONResponse):
            return gate
        events = await traffic_log.snapshot_dicts(site_id=site_id)
        return {"status": "ok", "site_id": site_id, "events": events}

    @router.get("/api/ai-status", response_model=None)
    async def worker_api_ai_status(request: Request) -> Any:
        gate = _require_admin_api(request)
        if isinstance(gate, JSONResponse):
            return gate
        return {"status": "ok", "site_id": site_id, "ai_second_pass": ai_second_pass_status()}

    app.include_router(router)
