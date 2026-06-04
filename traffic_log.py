"""SQLite-backed proxy traffic log (대시보드 탐지·차단 상세 유지, 재시작 후에도 보존)."""

from __future__ import annotations

import asyncio
import json
import os
import re
import sqlite3
import threading
from pathlib import Path
from typing import Any

from starlette.requests import Request
from zoneinfo import ZoneInfo
from datetime import datetime

TZ_SEOUL = ZoneInfo("Asia/Seoul")


def normalize_upstream_base_url(candidate: str) -> str:
    """SPA 브라우저 주소의 #fragment 제거·뒤 슬래시 정리. UPSTREAM_URL·프로필 힌트 공통 처리."""
    t = (candidate or "").strip()
    if not t:
        return ""
    if "#" in t:
        t = t.split("#", 1)[0].strip()
    while t.endswith("/"):
        t = t[:-1]
    return t


_DB_LOCK = threading.Lock()
_conn: sqlite3.Connection | None = None


def _db_path() -> str:
    raw = os.environ.get("TRAFFIC_LOG_DB", "").strip()
    if raw:
        return raw
    return str(Path(__file__).resolve().parent / "waf_traffic.sqlite3")


def _snapshot_limit() -> int:
    try:
        n = int(os.environ.get("TRAFFIC_LOG_SNAPSHOT_LIMIT", "500"))
    except ValueError:
        n = 500
    return max(1, min(n, 50_000))


def _max_stored_rows() -> int:
    try:
        n = int(os.environ.get("TRAFFIC_LOG_MAX_ROWS", "0"))
    except ValueError:
        n = 0
    return max(0, min(n, 500_000))


def _ensure_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(_db_path(), check_same_thread=False, timeout=30.0)
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA synchronous=NORMAL")
        _conn.execute("PRAGMA busy_timeout=60000")
        _conn.execute(
            """
            CREATE TABLE IF NOT EXISTS traffic_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time_iso TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                blocked INTEGER NOT NULL,
                block_findings_json TEXT NOT NULL,
                site_id TEXT NOT NULL DEFAULT ''
            )
            """
        )
        _conn.commit()
        # 기존 DB 마이그레이션: site_id 컬럼 추가 (site_id 인덱스 생성 전에 실행)
        try:
            _conn.execute(
                "ALTER TABLE traffic_events ADD COLUMN site_id TEXT NOT NULL DEFAULT ''"
            )
            _conn.commit()
        except sqlite3.OperationalError:
            pass  # 이미 존재하는 컬럼
        _conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_traffic_events_client ON traffic_events(client_ip)"
        )
        _conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_traffic_events_site ON traffic_events(site_id)"
        )
        _conn.commit()
        _conn.execute(
            """
            CREATE TABLE IF NOT EXISTS site_profiles (
                site_id TEXT PRIMARY KEY NOT NULL,
                display_label TEXT NOT NULL DEFAULT '',
                public_url TEXT NOT NULL DEFAULT '',
                last_seen_iso TEXT NOT NULL DEFAULT '',
                waf_enabled INTEGER NOT NULL DEFAULT 1,
                install_registered INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        _conn.commit()
        try:
            _conn.execute(
                "ALTER TABLE site_profiles ADD COLUMN waf_enabled INTEGER NOT NULL DEFAULT 1"
            )
            _conn.commit()
        except sqlite3.OperationalError:
            pass  # 컬럼 이미 존재
        try:
            _conn.execute(
                "ALTER TABLE site_profiles ADD COLUMN install_registered INTEGER NOT NULL DEFAULT 0"
            )
            _conn.commit()
        except sqlite3.OperationalError:
            pass  # 컬럼 이미 존재
    return _conn


def clear() -> None:
    with _DB_LOCK:
        c = _ensure_conn()
        c.execute("DELETE FROM traffic_events")
        c.commit()


async def clear_all_async() -> None:
    await asyncio.to_thread(clear)


def _clear_by_site_sync(site_id: str) -> None:
    with _DB_LOCK:
        c = _ensure_conn()
        c.execute("DELETE FROM traffic_events WHERE site_id = ?", (site_id or "",))
        c.commit()


async def clear_by_site_async(site_id: str) -> None:
    await asyncio.to_thread(_clear_by_site_sync, site_id)


def _reopen_database_sync(raw: str) -> None:
    """현재 연결을 닫고 TRAFFIC_LOG_DB 를 반영한 뒤 새 SQLite 파일(또는 :memory:)에 연결한다."""
    global _conn
    t = raw.strip()
    if len(t) > 2048 or "\x00" in t:
        raise ValueError("TRAFFIC_LOG_DB 가 너무 길거나 허용되지 않는 문자가 있습니다.")
    with _DB_LOCK:
        if _conn is not None:
            try:
                _conn.close()
            except Exception:
                pass
            _conn = None
        if t == "":
            os.environ.pop("TRAFFIC_LOG_DB", None)
        else:
            os.environ["TRAFFIC_LOG_DB"] = t
        _ensure_conn()


async def reopen_database_async(raw: str) -> None:
    await asyncio.to_thread(_reopen_database_sync, raw)


def _maybe_prune(conn: sqlite3.Connection) -> None:
    cap = _max_stored_rows()
    if cap <= 0:
        return
    n = int(conn.execute("SELECT COUNT(*) FROM traffic_events").fetchone()[0])
    if n <= cap:
        return
    to_drop = n - cap
    conn.execute(
        """
        DELETE FROM traffic_events WHERE id IN (
            SELECT id FROM traffic_events ORDER BY id ASC LIMIT ?
        )
        """,
        (to_drop,),
    )


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


def _row_to_event_dict(row: tuple[Any, ...]) -> dict[str, Any]:
    (
        eid,
        time_iso,
        client_ip,
        method,
        path,
        user_agent,
        status_code,
        blocked_int,
        bf_json,
        site_id,
    ) = row
    try:
        bf = json.loads(bf_json)
        if not isinstance(bf, list):
            bf = []
    except json.JSONDecodeError:
        bf = []
    return {
        "id": int(eid),
        "time_iso": str(time_iso),
        "client_ip": str(client_ip),
        "method": str(method),
        "path": str(path),
        "user_agent": str(user_agent),
        "status_code": int(status_code),
        "blocked": bool(blocked_int),
        "block_findings": bf,
        "site_id": str(site_id or ""),
    }


def _record_sync(
    request: Request,
    *,
    status_code: int,
    blocked: bool,
    block_findings: tuple[dict[str, str], ...] = (),
    site_id: str = "",
) -> None:
    if not should_log_path(request.url.path):
        return
    ua = request.headers.get("user-agent") or "—"
    if len(ua) > 220:
        ua = ua[:217] + "…"
    time_iso = datetime.now(TZ_SEOUL).strftime("%Y-%m-%d %H:%M:%S")
    cip = _client_ip(request)
    bf: tuple[dict[str, str], ...] = block_findings if blocked else ()
    payload = json.dumps([dict(x) for x in bf], ensure_ascii=False)
    with _DB_LOCK:
        conn = _ensure_conn()
        conn.execute(
            """
            INSERT INTO traffic_events (
                time_iso, client_ip, method, path, user_agent,
                status_code, blocked, block_findings_json, site_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                time_iso,
                cip,
                request.method.upper(),
                request.url.path or "/",
                ua,
                int(status_code),
                1 if blocked else 0,
                payload,
                site_id or "",
            ),
        )
        _maybe_prune(conn)
        conn.commit()


async def record(
    request: Request,
    *,
    status_code: int,
    blocked: bool,
    block_findings: tuple[dict[str, str], ...] = (),
    site_id: str = "",
) -> None:
    await asyncio.to_thread(
        _record_sync,
        request,
        status_code=status_code,
        blocked=blocked,
        block_findings=block_findings,
        site_id=site_id,
    )


def _trim_text(value: Any, default: str = "—", limit: int = 512) -> str:
    text = str(value if value is not None else default)
    if not text:
        text = default
    if len(text) > limit:
        return text[: max(0, limit - 1)] + "…"
    return text


def _record_event_dict_sync(event: dict[str, Any]) -> None:
    """중앙 수신 API용: 센서가 보낸 JSON 이벤트를 직접 저장."""
    path = _trim_text(event.get("path"), "/", 2048)
    if not should_log_path(path):
        return
    findings_raw = event.get("block_findings") or []
    if not isinstance(findings_raw, list):
        findings_raw = []
    findings = [x for x in findings_raw if isinstance(x, dict)]
    payload = json.dumps(findings, ensure_ascii=False)
    time_iso = _trim_text(
        event.get("time_iso") or datetime.now(TZ_SEOUL).strftime("%Y-%m-%d %H:%M:%S"),
        limit=64,
    )
    sid_eff = _trim_text(event.get("site_id"), "", 128).strip()
    meta_label = _trim_text(event.get("sensor_label"), "", 140)
    meta_url = _trim_text(event.get("sensor_public_origin"), "", 520)
    with _DB_LOCK:
        conn = _ensure_conn()
        conn.execute(
            """
            INSERT INTO traffic_events (
                time_iso, client_ip, method, path, user_agent,
                status_code, blocked, block_findings_json, site_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                time_iso,
                _trim_text(event.get("client_ip"), "—", 128),
                _trim_text(event.get("method"), "GET", 16).upper(),
                path,
                _trim_text(event.get("user_agent"), "—", 220),
                int(event.get("status_code") or 0),
                1 if bool(event.get("blocked")) else 0,
                payload,
                sid_eff,
            ),
        )
        _touch_site_profile_after_event(
            conn,
            sid_eff,
            label_in=str(meta_label or ""),
            url_in=str(meta_url or ""),
            seen_iso=str(time_iso or ""),
        )
        _maybe_prune(conn)
        conn.commit()


async def record_event_dict(event: dict[str, Any]) -> None:
    await asyncio.to_thread(_record_event_dict_sync, event)


def _touch_site_profile_after_event(
    conn: sqlite3.Connection,
    site_id: str,
    *,
    label_in: str,
    url_in: str,
    seen_iso: str,
) -> None:
    sid = site_id.strip()
    if not sid:
        return
    lbl = (label_in or "").strip()[:128]
    url = (url_in or "").strip()[:512]
    conn.execute(
        """
        INSERT INTO site_profiles (site_id, display_label, public_url, last_seen_iso, waf_enabled)
        VALUES (?, ?, ?, ?, 1)
        ON CONFLICT(site_id) DO UPDATE SET
            display_label = CASE WHEN excluded.display_label != ''
                THEN excluded.display_label ELSE site_profiles.display_label END,
            public_url = CASE WHEN excluded.public_url != ''
                THEN excluded.public_url ELSE site_profiles.public_url END,
            last_seen_iso = excluded.last_seen_iso
        """,
        (sid, lbl, url, (seen_iso or "")[:64]),
    )


def _upsert_registration_site_profile_sync(
    site_id: str,
    username: str,
    public_hint: str = "",
    install_registered: bool = False,
) -> None:
    """회원가입 직후: 표시 이름·업스트림 URL 힌트를 site_profiles 에 남김 (ingest/traffic 없을 때 참고)."""
    sid = (site_id or "").strip()
    if not sid:
        return
    lbl = (username or "").strip()[:128]
    pub = (public_hint or "").strip()[:512]
    seen = datetime.now(TZ_SEOUL).strftime("%Y-%m-%d %H:%M:%S")
    with _DB_LOCK:
        conn = _ensure_conn()
        conn.execute(
            """
            INSERT INTO site_profiles (site_id, display_label, public_url, last_seen_iso, waf_enabled, install_registered)
            VALUES (?, ?, ?, ?, 1, ?)
            ON CONFLICT(site_id) DO UPDATE SET
                display_label = CASE WHEN excluded.display_label != ''
                    THEN excluded.display_label ELSE site_profiles.display_label END,
                public_url = CASE WHEN excluded.public_url != ''
                    THEN excluded.public_url ELSE site_profiles.public_url END,
                last_seen_iso = excluded.last_seen_iso,
                install_registered = CASE WHEN excluded.install_registered = 1
                    THEN 1 ELSE site_profiles.install_registered END
            """,
            (sid, lbl, pub, seen, 1 if install_registered else 0),
        )
        conn.commit()


async def upsert_registration_site_profile(
    site_id: str,
    username: str,
    public_hint: str = "",
    install_registered: bool = False,
) -> None:
    await asyncio.to_thread(
        _upsert_registration_site_profile_sync,
        site_id,
        username,
        public_hint,
        install_registered,
    )


def get_site_profile_public_url_sync(site_id: str) -> str:
    """site_profiles 에 저장된 public_url 힌트 (회원가입·ingest 에서 채워짐)."""
    sid = (site_id or "").strip()
    if not sid:
        return ""
    with _DB_LOCK:
        conn = _ensure_conn()
        row = conn.execute(
            "SELECT public_url FROM site_profiles WHERE site_id = ?",
            (sid,),
        ).fetchone()
    if row is None:
        return ""
    u = normalize_upstream_base_url(str(row[0] or ""))
    return u if u.startswith(("http://", "https://")) else ""


async def get_site_profile_public_url(site_id: str) -> str:
    return await asyncio.to_thread(get_site_profile_public_url_sync, site_id)


def get_site_install_registered_sync(site_id: str) -> bool:
    """사이트 연결 화면에서 사용자가 원본 주소 등록을 완료했는지."""
    sid = (site_id or "").strip()
    if not sid:
        return False
    with _DB_LOCK:
        conn = _ensure_conn()
        row = conn.execute(
            "SELECT COALESCE(install_registered, 0) FROM site_profiles WHERE site_id = ?",
            (sid,),
        ).fetchone()
    if row is None:
        return False
    return bool(int(row[0] or 0))


async def get_site_install_registered(site_id: str) -> bool:
    return await asyncio.to_thread(get_site_install_registered_sync, site_id)


def _sites_manifest_sync() -> list[dict[str, Any]]:
    """traffic_events 에 나타난 site_id + 선택적 프로필(표시 이름·프록시 URL)."""
    with _DB_LOCK:
        conn = _ensure_conn()
        cur = conn.execute(
            """
            SELECT DISTINCT site_id FROM traffic_events
            WHERE site_id IS NOT NULL AND trim(site_id) != ''
            ORDER BY site_id
            """
        )
        ids_in_order = [str(r[0]) for r in cur.fetchall()]
        labels: dict[str, tuple[str, str, bool]] = {}
        for row in conn.execute(
            """
            SELECT site_id, display_label, public_url, COALESCE(waf_enabled, 1)
            FROM site_profiles
            """
        ):
            labels[str(row[0])] = (
                str(row[1] or ""),
                str(row[2] or ""),
                bool(int(row[3])),
            )
    manifest: list[dict[str, Any]] = []
    for sid in ids_in_order:
        lab, pub, waf_on = labels.get(sid, ("", "", True))
        manifest.append(
            {
                "site_id": sid,
                "label": (lab.strip() or sid),
                "public_url": pub.strip(),
                "waf_enabled": waf_on,
            }
        )
    return manifest


async def sites_manifest() -> list[dict[str, Any]]:
    return await asyncio.to_thread(_sites_manifest_sync)


def get_site_waf_enabled_sync(site_id: str) -> bool:
    """site_profiles 없으면 기본 True(차단 정책 켜짐)."""
    sid = (site_id or "").strip()
    if not sid:
        return True
    with _DB_LOCK:
        conn = _ensure_conn()
        row = conn.execute(
            "SELECT COALESCE(waf_enabled, 1) FROM site_profiles WHERE site_id = ?",
            (sid,),
        ).fetchone()
    if row is None:
        return True
    return bool(int(row[0]))


def set_site_waf_enabled_sync(site_id: str, enabled: bool) -> None:
    sid = (site_id or "").strip()
    if not sid:
        raise ValueError("site_id is required")
    v = 1 if enabled else 0
    with _DB_LOCK:
        conn = _ensure_conn()
        conn.execute(
            """
            INSERT INTO site_profiles (site_id, display_label, public_url, last_seen_iso, waf_enabled)
            VALUES (?, '', '', datetime('now'), ?)
            ON CONFLICT(site_id) DO UPDATE SET waf_enabled = excluded.waf_enabled
            """,
            (sid, v),
        )
        conn.commit()


async def get_site_waf_enabled(site_id: str) -> bool:
    return await asyncio.to_thread(get_site_waf_enabled_sync, site_id)


async def set_site_waf_enabled(site_id: str, enabled: bool) -> None:
    await asyncio.to_thread(set_site_waf_enabled_sync, site_id, enabled)


def _snapshot_dicts_sync(site_id: str = "") -> list[dict[str, Any]]:
    lim = _snapshot_limit()
    with _DB_LOCK:
        conn = _ensure_conn()
        if site_id:
            cur = conn.execute(
                """
                SELECT id, time_iso, client_ip, method, path, user_agent,
                       status_code, blocked, block_findings_json, site_id
                FROM traffic_events
                WHERE site_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (site_id, lim),
            )
        else:
            cur = conn.execute(
                """
                SELECT id, time_iso, client_ip, method, path, user_agent,
                       status_code, blocked, block_findings_json, site_id
                FROM traffic_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (lim,),
            )
        return [_row_to_event_dict(r) for r in cur.fetchall()]


async def snapshot_dicts(site_id: str = "") -> list[dict[str, Any]]:
    return await asyncio.to_thread(_snapshot_dicts_sync, site_id)


def _clients_snapshot_sync(site_id: str = "") -> dict[str, Any]:
    with _DB_LOCK:
        conn = _ensure_conn()
        if site_id:
            cur = conn.execute(
                """
                SELECT
                    e.client_ip,
                    MIN(e.time_iso) AS first_seen,
                    MAX(e.time_iso) AS last_seen,
                    COUNT(*) AS requests,
                    (
                        SELECT x.user_agent FROM traffic_events x
                        WHERE x.client_ip = e.client_ip AND x.site_id = ?
                        ORDER BY x.id DESC LIMIT 1
                    ) AS user_agent
                FROM traffic_events e
                WHERE e.site_id = ?
                GROUP BY e.client_ip
                ORDER BY last_seen DESC
                """,
                (site_id, site_id),
            )
        else:
            cur = conn.execute(
                """
                SELECT
                    e.client_ip,
                    MIN(e.time_iso) AS first_seen,
                    MAX(e.time_iso) AS last_seen,
                    COUNT(*) AS requests,
                    (
                        SELECT x.user_agent FROM traffic_events x
                        WHERE x.client_ip = e.client_ip
                        ORDER BY x.id DESC LIMIT 1
                    ) AS user_agent
                FROM traffic_events e
                GROUP BY e.client_ip
                ORDER BY last_seen DESC
                """
            )
        items: list[dict[str, Any]] = []
        for row in cur.fetchall():
            items.append(
                {
                    "client_ip": row[0],
                    "first_seen": row[1],
                    "last_seen": row[2],
                    "requests": int(row[3]),
                    "user_agent": row[4] or "—",
                }
            )
        return {"status": "ok", "unique_clients": len(items), "clients": items}


async def clients_snapshot(site_id: str = "") -> dict[str, Any]:
    return await asyncio.to_thread(_clients_snapshot_sync, site_id)


def _top_counts(counts: dict[str, int], n: int) -> list[dict[str, Any]]:
    items = sorted(counts.items(), key=lambda x: (-x[1], x[0]))[:n]
    return [{"key": k, "count": v} for k, v in items]


def _stats_snapshot_sync(site_id: str = "") -> dict[str, Any]:
    lim = _snapshot_limit()
    with _DB_LOCK:
        conn = _ensure_conn()
        if site_id:
            total = int(
                conn.execute(
                    "SELECT COUNT(*) FROM traffic_events WHERE site_id = ?", (site_id,)
                ).fetchone()[0]
            )
            blocked_n = int(
                conn.execute(
                    "SELECT COUNT(*) FROM traffic_events WHERE blocked = 1 AND site_id = ?",
                    (site_id,),
                ).fetchone()[0]
            )
            cur = conn.execute(
                "SELECT block_findings_json FROM traffic_events WHERE blocked = 1 AND site_id = ?",
                (site_id,),
            )
        else:
            total = int(conn.execute("SELECT COUNT(*) FROM traffic_events").fetchone()[0])
            blocked_n = int(
                conn.execute("SELECT COUNT(*) FROM traffic_events WHERE blocked = 1").fetchone()[0]
            )
            cur = conn.execute(
                "SELECT block_findings_json FROM traffic_events WHERE blocked = 1"
            )
        rule_counts: dict[str, int] = {}
        attack_counts: dict[str, int] = {}
        for (bf_json,) in cur.fetchall():
            try:
                findings = json.loads(bf_json)
            except json.JSONDecodeError:
                continue
            if not isinstance(findings, list):
                continue
            for bf in findings:
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
        "buffer_capacity": lim,
        "total_logged": total,
        "blocked_count": blocked_n,
        "passed_count": total - blocked_n,
        "block_ratio": round(ratio, 4),
        "top_rule_ids": _top_counts(rule_counts, 5),
        "top_attack_types": _top_counts(attack_counts, 5),
        "max_stored_rows": _max_stored_rows(),
    }


async def stats_snapshot(site_id: str = "") -> dict[str, Any]:
    return await asyncio.to_thread(_stats_snapshot_sync, site_id)


def _sites_list_sync() -> list[str]:
    with _DB_LOCK:
        conn = _ensure_conn()
        cur = conn.execute(
            "SELECT DISTINCT site_id FROM traffic_events WHERE site_id != '' ORDER BY site_id"
        )
        return [str(r[0]) for r in cur.fetchall()]


async def sites_list() -> list[str]:
    return await asyncio.to_thread(_sites_list_sync)


def _delete_by_id_sync(event_id: int) -> bool:
    with _DB_LOCK:
        conn = _ensure_conn()
        cur = conn.execute("DELETE FROM traffic_events WHERE id = ?", (int(event_id),))
        conn.commit()
        return cur.rowcount > 0


async def delete_by_id(event_id: int) -> bool:
    return await asyncio.to_thread(_delete_by_id_sync, event_id)


def _store_info_sync() -> dict[str, Any]:
    env_raw = os.environ.get("TRAFFIC_LOG_DB", "").strip()
    default_fp = str(Path(__file__).resolve().parent / "waf_traffic.sqlite3")
    with _DB_LOCK:
        conn = _ensure_conn()
        stored = int(conn.execute("SELECT COUNT(*) FROM traffic_events").fetchone()[0])
    return {
        "status": "ok",
        "traffic_log_db_env": env_raw,
        "traffic_log_db_resolved": _db_path(),
        "traffic_log_db_default_hint": default_fp,
        "snapshot_limit": _snapshot_limit(),
        "max_stored_rows": _max_stored_rows(),
        "stored_row_count": stored,
        "db_path_change_requires_restart": False,
    }


async def store_info() -> dict[str, Any]:
    return await asyncio.to_thread(_store_info_sync)


_SQL_CONSOLE_MAX_ROWS = 2000
_SQL_CONSOLE_MAX_LEN = 50_000
_SAFE_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _pragma_is_read_only(low: str) -> bool:
    if any(x in low for x in ("attach", "detach", "writable_schema")):
        return False
    if "=" in low:
        return False
    return True


def _validate_console_sql(sql: str) -> str:
    raw = sql.strip()
    if not raw:
        raise ValueError("SQL이 비었습니다.")
    if len(raw) > _SQL_CONSOLE_MAX_LEN:
        raise ValueError("SQL이 너무 깁니다.")
    if "\x00" in raw:
        raise ValueError("NULL 문자는 허용되지 않습니다.")
    one = raw.rstrip().rstrip(";").strip()
    if ";" in one:
        raise ValueError("한 번에 하나의 문장만 실행할 수 있습니다. 세미콜론(;)은 맨 끝에만 올 수 있습니다.")
    low = one.lstrip().lower()
    if low.startswith("explain"):
        return one
    if low.startswith("select") or low.startswith("with"):
        return one
    if low.startswith("pragma"):
        if not _pragma_is_read_only(low):
            raise ValueError("이 PRAGMA는 콘솔에서 허용되지 않습니다.")
        return one
    raise ValueError(
        "읽기 전용 콘솔입니다. SELECT, WITH, EXPLAIN, 또는 조회용 PRAGMA 만 실행할 수 있습니다."
    )


def _cell_json(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, bytes):
        return "0x" + v.hex()
    if isinstance(v, (int, float, str, bool)):
        return v
    return str(v)


def _schema_snapshot_sync() -> dict[str, Any]:
    with _DB_LOCK:
        conn = _ensure_conn()
        conn.row_factory = sqlite3.Row
        path = _db_path()
        cur = conn.execute(
            """
            SELECT name, type FROM sqlite_master
            WHERE type IN ('table', 'view')
              AND name NOT LIKE 'sqlite_%'
            ORDER BY type DESC, name
            """
        )
        tables: list[dict[str, Any]] = []
        for row in cur.fetchall():
            tname = str(row["name"])
            ttype = str(row["type"])
            if not _SAFE_IDENT.fullmatch(tname):
                continue
            safe = tname
            cols: list[dict[str, Any]] = []
            try:
                for ci in conn.execute(f'PRAGMA table_info("{safe}")'):
                    cols.append(
                        {
                            "name": str(ci["name"]),
                            "type": (ci["type"] or "") or "",
                            "notnull": bool(ci["notnull"]),
                            "pk": int(ci["pk"]),
                            "default": ci["dflt_value"],
                        }
                    )
            except sqlite3.Error:
                cols = []
            tables.append({"name": safe, "type": ttype, "columns": cols})
    return {
        "status": "ok",
        "db_display_name": Path(path).name if path != ":memory:" else ":memory:",
        "db_path_resolved": path,
        "tables": tables,
    }


def _run_console_query_sync(sql: str) -> dict[str, Any]:
    validated = _validate_console_sql(sql)
    with _DB_LOCK:
        conn = _ensure_conn()
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute(validated)
        except sqlite3.Error as exc:
            raise ValueError(str(exc)[:500]) from exc
        if cur.description:
            columns = [d[0] for d in cur.description]
        else:
            columns = []
        rows_out: list[list[Any]] = []
        truncated = False
        for i, row in enumerate(cur):
            if i >= _SQL_CONSOLE_MAX_ROWS:
                truncated = True
                break
            rows_out.append([_cell_json(row[c]) for c in columns])
    return {
        "status": "ok",
        "columns": columns,
        "rows": rows_out,
        "row_count": len(rows_out),
        "truncated": truncated,
        "max_rows": _SQL_CONSOLE_MAX_ROWS,
    }


async def schema_snapshot() -> dict[str, Any]:
    return await asyncio.to_thread(_schema_snapshot_sync)


async def run_console_query(sql: str) -> dict[str, Any]:
    return await asyncio.to_thread(_run_console_query_sync, sql)
