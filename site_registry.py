"""멀티사이트 WAF — 사이트 레지스트리 (SQLite 기반).

sites, site_routes, site_policies, site_exceptions, ip_policies,
site_requests(신규), site_detections, audit_logs 테이블을 관리한다.

WAF 프록시는 요청의 Host 헤더로 lookup_route(domain) 를 호출해
origin URL 과 정책을 받아온다.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import sqlite3
import threading
import time as _time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

_TZ_SEOUL = ZoneInfo("Asia/Seoul")
_LOCK = threading.Lock()
_conn: sqlite3.Connection | None = None


def _db_path() -> str:
    raw = os.environ.get("WAF_SITES_DB", "").strip()
    if raw:
        return raw
    return str(Path(__file__).resolve().parent / "waf_traffic.sqlite3")


def _ensure_conn() -> sqlite3.Connection:
    global _conn
    if _conn is not None:
        return _conn
    path = _db_path()
    _conn = sqlite3.connect(path, check_same_thread=False, timeout=30.0)
    _conn.row_factory = sqlite3.Row
    _conn.execute("PRAGMA journal_mode=WAL")
    _conn.execute("PRAGMA synchronous=NORMAL")
    _conn.execute("PRAGMA busy_timeout=60000")
    _conn.execute("PRAGMA foreign_keys=ON")
    _create_tables(_conn)
    return _conn


def _create_tables(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS sites (
        site_id        TEXT PRIMARY KEY NOT NULL,
        display_name   TEXT NOT NULL DEFAULT '',
        owner_username TEXT NOT NULL DEFAULT '',
        status         TEXT NOT NULL DEFAULT 'active',
        created_at     TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS site_routes (
        route_id   INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id    TEXT NOT NULL,
        domain     TEXT NOT NULL UNIQUE,
        origin_url TEXT NOT NULL,
        tls_mode   TEXT NOT NULL DEFAULT 'none_local',
        verify_tls INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS site_policies (
        site_id                  TEXT PRIMARY KEY NOT NULL,
        mode                     TEXT NOT NULL DEFAULT 'block',
        min_severity             TEXT NOT NULL DEFAULT 'high',
        ai_second_pass_enabled   INTEGER NOT NULL DEFAULT 0,
        ai_block_min_confidence  REAL NOT NULL DEFAULT 0.7,
        fail_mode                TEXT NOT NULL DEFAULT 'fail_open',
        updated_at               TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS site_rule_settings (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id           TEXT NOT NULL,
        rule_id           TEXT NOT NULL,
        enabled           INTEGER NOT NULL DEFAULT 1,
        severity_override TEXT NOT NULL DEFAULT '',
        updated_at        TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE(site_id, rule_id)
    );
    CREATE TABLE IF NOT EXISTS site_exceptions (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id      TEXT NOT NULL,
        path_pattern TEXT NOT NULL,
        rule_id      TEXT NOT NULL DEFAULT '',
        method       TEXT NOT NULL DEFAULT '',
        reason       TEXT NOT NULL DEFAULT '',
        enabled      INTEGER NOT NULL DEFAULT 1,
        created_by   TEXT NOT NULL DEFAULT '',
        created_at   TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS ip_policies (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id  TEXT NOT NULL,
        ip_cidr  TEXT NOT NULL,
        action   TEXT NOT NULL DEFAULT 'block',
        reason   TEXT NOT NULL DEFAULT '',
        enabled  INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS site_requests (
        request_id   INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id      TEXT NOT NULL DEFAULT '',
        domain       TEXT NOT NULL DEFAULT '',
        time_iso     TEXT NOT NULL,
        client_ip    TEXT NOT NULL DEFAULT '',
        method       TEXT NOT NULL DEFAULT '',
        path         TEXT NOT NULL DEFAULT '',
        query_string TEXT NOT NULL DEFAULT '',
        user_agent   TEXT NOT NULL DEFAULT '',
        status_code  INTEGER NOT NULL DEFAULT 0,
        detected     INTEGER NOT NULL DEFAULT 0,
        blocked      INTEGER NOT NULL DEFAULT 0,
        policy_mode  TEXT NOT NULL DEFAULT '',
        origin_url   TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS site_detections (
        detection_id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id   INTEGER NOT NULL DEFAULT 0,
        site_id      TEXT NOT NULL DEFAULT '',
        owasp_id     TEXT NOT NULL DEFAULT '',
        rule_id      TEXT NOT NULL DEFAULT '',
        attack_type  TEXT NOT NULL DEFAULT '',
        severity     TEXT NOT NULL DEFAULT '',
        location     TEXT NOT NULL DEFAULT '',
        evidence     TEXT NOT NULL DEFAULT '',
        action       TEXT NOT NULL DEFAULT 'detect'
    );
    CREATE TABLE IF NOT EXISTS site_ai_decisions (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id   INTEGER NOT NULL DEFAULT 0,
        site_id      TEXT NOT NULL DEFAULT '',
        should_block INTEGER NOT NULL DEFAULT 0,
        confidence   REAL NOT NULL DEFAULT 0.0,
        attack_type  TEXT NOT NULL DEFAULT '',
        reason       TEXT NOT NULL DEFAULT '',
        final_action TEXT NOT NULL DEFAULT 'allow'
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        time_iso    TEXT NOT NULL DEFAULT (datetime('now')),
        username    TEXT NOT NULL DEFAULT '',
        site_id     TEXT NOT NULL DEFAULT '',
        action      TEXT NOT NULL DEFAULT '',
        target      TEXT NOT NULL DEFAULT '',
        before_json TEXT NOT NULL DEFAULT '{}',
        after_json  TEXT NOT NULL DEFAULT '{}',
        client_ip   TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_site_routes_domain    ON site_routes(domain);
    CREATE INDEX IF NOT EXISTS idx_site_routes_site      ON site_routes(site_id);
    CREATE INDEX IF NOT EXISTS idx_site_requests_site_t  ON site_requests(site_id, time_iso);
    CREATE INDEX IF NOT EXISTS idx_site_requests_blocked ON site_requests(blocked);
    CREATE INDEX IF NOT EXISTS idx_site_detections_rule  ON site_detections(rule_id);
    CREATE INDEX IF NOT EXISTS idx_site_detections_req   ON site_detections(request_id);
    CREATE INDEX IF NOT EXISTS idx_audit_site_time       ON audit_logs(site_id, time_iso);
    CREATE INDEX IF NOT EXISTS idx_ip_policies_site      ON ip_policies(site_id);
    CREATE INDEX IF NOT EXISTS idx_exceptions_site       ON site_exceptions(site_id);
    """)
    conn.commit()


def _normalize_domain(domain: str) -> str:
    d = (domain or "").strip().lower()
    if d.startswith("["):
        idx = d.rfind("]")
        if idx >= 0:
            d = d[: idx + 1]
    elif ":" in d:
        d = d.rsplit(":", 1)[0]
    return d


_ALLOW_LOCAL_ORIGIN = os.environ.get("WAF_ALLOW_LOCAL_ORIGIN", "true").strip().lower() not in (
    "0", "false", "no", "off"
)


def validate_origin_url(origin_url: str) -> str | None:
    from urllib.parse import urlparse
    url = (origin_url or "").strip()
    if not url:
        return "origin URL이 비어 있습니다."
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "origin URL은 http:// 또는 https:// 로 시작해야 합니다."
    host = (parsed.hostname or "").lower()
    if not host:
        return "origin URL에 호스트가 없습니다."
    return None


@dataclass
class RouteConfig:
    site_id: str
    domain: str
    origin_url: str
    mode: str
    min_severity: str
    ai_enabled: bool
    ai_min_confidence: float
    fail_mode: str


_ROUTE_CACHE: dict[str, tuple[float, "RouteConfig | None"]] = {}
_ROUTE_CACHE_TTL = float(os.environ.get("WAF_ROUTE_CACHE_TTL", "5"))
_ROUTE_CACHE_LOCK = threading.Lock()


def _invalidate_route_cache() -> None:
    with _ROUTE_CACHE_LOCK:
        _ROUTE_CACHE.clear()


def lookup_route(host: str) -> "RouteConfig | None":
    domain = _normalize_domain(host)
    if not domain:
        return None
    now = _time.monotonic()
    with _ROUTE_CACHE_LOCK:
        if domain in _ROUTE_CACHE:
            ts, cfg = _ROUTE_CACHE[domain]
            if now - ts < _ROUTE_CACHE_TTL:
                return cfg
    cfg = _lookup_route_from_db(domain)
    with _ROUTE_CACHE_LOCK:
        _ROUTE_CACHE[domain] = (now, cfg)
    return cfg


def _lookup_route_from_db(domain: str) -> "RouteConfig | None":
    with _LOCK:
        conn = _ensure_conn()
        row = conn.execute(
            """
            SELECT r.site_id, r.domain, r.origin_url,
                   COALESCE(p.mode,'block')              AS mode,
                   COALESCE(p.min_severity,'high')       AS min_severity,
                   COALESCE(p.ai_second_pass_enabled,0)  AS ai_enabled,
                   COALESCE(p.ai_block_min_confidence,0.7) AS ai_min_confidence,
                   COALESCE(p.fail_mode,'fail_open')     AS fail_mode,
                   COALESCE(s.status,'active')           AS status
            FROM site_routes r
            JOIN sites s ON s.site_id = r.site_id
            LEFT JOIN site_policies p ON p.site_id = r.site_id
            WHERE r.domain = ?
            """,
            (domain,),
        ).fetchone()
    if row is None:
        return None
    if row["status"] != "active":
        return None
    return RouteConfig(
        site_id=row["site_id"],
        domain=row["domain"],
        origin_url=row["origin_url"],
        mode=row["mode"],
        min_severity=row["min_severity"],
        ai_enabled=bool(row["ai_enabled"]),
        ai_min_confidence=float(row["ai_min_confidence"]),
        fail_mode=row["fail_mode"],
    )


def check_ip_policy(site_id: str, client_ip: str) -> "str | None":
    if not client_ip or not site_id:
        return None
    with _LOCK:
        conn = _ensure_conn()
        rows = conn.execute(
            "SELECT ip_cidr, action FROM ip_policies WHERE site_id=? AND enabled=1",
            (site_id,),
        ).fetchall()
    try:
        addr = ipaddress.ip_address(client_ip.split("%")[0])
    except ValueError:
        return None
    for row in rows:
        try:
            net = ipaddress.ip_network(row["ip_cidr"], strict=False)
            if addr in net:
                return row["action"]
        except ValueError:
            continue
    return None


def is_exception_path(site_id: str, path: str, method: str = "", rule_id: str = "") -> bool:
    with _LOCK:
        conn = _ensure_conn()
        rows = conn.execute(
            "SELECT path_pattern, rule_id, method FROM site_exceptions WHERE site_id=? AND enabled=1",
            (site_id,),
        ).fetchall()
    for row in rows:
        pattern = row["path_pattern"]
        exc_rule = row["rule_id"]
        exc_method = (row["method"] or "").upper()
        if exc_method and method and exc_method != method.upper():
            continue
        if exc_rule and rule_id and exc_rule != rule_id:
            continue
        pat = re.escape(pattern).replace(r"\*", ".*")
        if re.fullmatch(pat, path):
            return True
    return False


def _now_iso() -> str:
    return datetime.now(_TZ_SEOUL).strftime("%Y-%m-%d %H:%M:%S")


def _gen_site_id(domain: str) -> str:
    base = re.sub(r"[^a-z0-9]", "_", domain.lower())[:20]
    suffix = secrets.token_hex(3)
    return f"{base}_{suffix}"


def create_site(
    *,
    display_name: str,
    domain: str,
    origin_url: str,
    owner_username: str = "admin",
    mode: str = "block",
    min_severity: str = "high",
) -> dict[str, Any]:
    err = validate_origin_url(origin_url)
    if err:
        raise ValueError(err)
    domain = _normalize_domain(domain)
    if not domain:
        raise ValueError("도메인이 비어 있습니다.")
    site_id = _gen_site_id(domain)
    now = _now_iso()
    with _LOCK:
        conn = _ensure_conn()
        existing = conn.execute(
            "SELECT route_id FROM site_routes WHERE domain=?", (domain,)
        ).fetchone()
        if existing:
            raise ValueError(f"도메인 '{domain}'이 이미 등록되어 있습니다.")
        conn.execute(
            "INSERT INTO sites (site_id, display_name, owner_username, status, created_at, updated_at)"
            " VALUES (?,?,?,'active',?,?)",
            (site_id, display_name, owner_username, now, now),
        )
        conn.execute(
            "INSERT INTO site_routes (site_id, domain, origin_url, created_at, updated_at)"
            " VALUES (?,?,?,?,?)",
            (site_id, domain, origin_url.strip().rstrip("/"), now, now),
        )
        conn.execute(
            "INSERT INTO site_policies (site_id, mode, min_severity, updated_at)"
            " VALUES (?,?,?,?)",
            (site_id, mode, min_severity, now),
        )
        conn.commit()
    _invalidate_route_cache()
    return {"site_id": site_id, "domain": domain, "origin_url": origin_url}


def update_site(
    site_id: str,
    *,
    display_name: "str | None" = None,
    origin_url: "str | None" = None,
    status: "str | None" = None,
    mode: "str | None" = None,
    min_severity: "str | None" = None,
    ai_enabled: "bool | None" = None,
    fail_mode: "str | None" = None,
) -> None:
    if origin_url is not None:
        err = validate_origin_url(origin_url)
        if err:
            raise ValueError(err)
    now = _now_iso()
    with _LOCK:
        conn = _ensure_conn()
        if display_name is not None or status is not None:
            updates: list[str] = []
            params: list[Any] = []
            if display_name is not None:
                updates.append("display_name=?")
                params.append(display_name)
            if status is not None:
                updates.append("status=?")
                params.append(status)
            updates.append("updated_at=?")
            params.append(now)
            params.append(site_id)
            conn.execute(f"UPDATE sites SET {', '.join(updates)} WHERE site_id=?", params)
        if origin_url is not None:
            conn.execute(
                "UPDATE site_routes SET origin_url=?, updated_at=? WHERE site_id=?",
                (origin_url.strip().rstrip("/"), now, site_id),
            )
        pol_updates: list[str] = []
        pol_params: list[Any] = []
        if mode is not None:
            pol_updates.append("mode=?"); pol_params.append(mode)
        if min_severity is not None:
            pol_updates.append("min_severity=?"); pol_params.append(min_severity)
        if ai_enabled is not None:
            pol_updates.append("ai_second_pass_enabled=?"); pol_params.append(1 if ai_enabled else 0)
        if fail_mode is not None:
            pol_updates.append("fail_mode=?"); pol_params.append(fail_mode)
        if pol_updates:
            pol_updates.append("updated_at=?"); pol_params.append(now)
            pol_params.append(site_id)
            conn.execute(
                f"UPDATE site_policies SET {', '.join(pol_updates)} WHERE site_id=?",
                pol_params,
            )
        conn.commit()
    _invalidate_route_cache()


def delete_site(site_id: str) -> None:
    with _LOCK:
        conn = _ensure_conn()
        conn.execute("DELETE FROM site_policies WHERE site_id=?", (site_id,))
        conn.execute("DELETE FROM site_routes WHERE site_id=?", (site_id,))
        conn.execute("DELETE FROM site_exceptions WHERE site_id=?", (site_id,))
        conn.execute("DELETE FROM ip_policies WHERE site_id=?", (site_id,))
        conn.execute("DELETE FROM site_rule_settings WHERE site_id=?", (site_id,))
        conn.execute("DELETE FROM sites WHERE site_id=?", (site_id,))
        conn.commit()
    _invalidate_route_cache()


def list_sites(owner_username: "str | None" = None) -> list[dict[str, Any]]:
    with _LOCK:
        conn = _ensure_conn()
        if owner_username:
            rows = conn.execute(
                """SELECT s.site_id, s.display_name, s.owner_username, s.status,
                          s.created_at, s.updated_at,
                          r.domain, r.origin_url, r.tls_mode,
                          COALESCE(p.mode,'block')        AS mode,
                          COALESCE(p.min_severity,'high') AS min_severity,
                          COALESCE(p.ai_second_pass_enabled,0) AS ai_enabled,
                          COALESCE(p.fail_mode,'fail_open') AS fail_mode
                   FROM sites s
                   LEFT JOIN site_routes r ON r.site_id=s.site_id
                   LEFT JOIN site_policies p ON p.site_id=s.site_id
                   WHERE s.owner_username=? ORDER BY s.created_at DESC""",
                (owner_username,),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT s.site_id, s.display_name, s.owner_username, s.status,
                          s.created_at, s.updated_at,
                          r.domain, r.origin_url, r.tls_mode,
                          COALESCE(p.mode,'block')        AS mode,
                          COALESCE(p.min_severity,'high') AS min_severity,
                          COALESCE(p.ai_second_pass_enabled,0) AS ai_enabled,
                          COALESCE(p.fail_mode,'fail_open') AS fail_mode
                   FROM sites s
                   LEFT JOIN site_routes r ON r.site_id=s.site_id
                   LEFT JOIN site_policies p ON p.site_id=s.site_id
                   ORDER BY s.created_at DESC"""
            ).fetchall()
    return [dict(r) for r in rows]


def get_site(site_id: str) -> "dict[str, Any] | None":
    with _LOCK:
        conn = _ensure_conn()
        row = conn.execute(
            """SELECT s.site_id, s.display_name, s.owner_username, s.status,
                      s.created_at, s.updated_at,
                      r.domain, r.origin_url, r.tls_mode,
                      COALESCE(p.mode,'block')              AS mode,
                      COALESCE(p.min_severity,'high')       AS min_severity,
                      COALESCE(p.ai_second_pass_enabled,0)  AS ai_enabled,
                      COALESCE(p.ai_block_min_confidence,0.7) AS ai_min_confidence,
                      COALESCE(p.fail_mode,'fail_open')     AS fail_mode
               FROM sites s
               LEFT JOIN site_routes r ON r.site_id=s.site_id
               LEFT JOIN site_policies p ON p.site_id=s.site_id
               WHERE s.site_id=?""",
            (site_id,),
        ).fetchone()
    return dict(row) if row else None


def add_exception(
    site_id: str, path_pattern: str, *,
    rule_id: str = "", method: str = "", reason: str = "", created_by: str = "",
) -> int:
    with _LOCK:
        conn = _ensure_conn()
        cur = conn.execute(
            "INSERT INTO site_exceptions (site_id,path_pattern,rule_id,method,reason,created_by)"
            " VALUES (?,?,?,?,?,?)",
            (site_id, path_pattern, rule_id, method.upper(), reason, created_by),
        )
        conn.commit()
        return cur.lastrowid or 0


def delete_exception(exception_id: int) -> None:
    with _LOCK:
        conn = _ensure_conn()
        conn.execute("DELETE FROM site_exceptions WHERE id=?", (exception_id,))
        conn.commit()


def list_exceptions(site_id: str) -> list[dict[str, Any]]:
    with _LOCK:
        conn = _ensure_conn()
        rows = conn.execute(
            "SELECT * FROM site_exceptions WHERE site_id=? ORDER BY id", (site_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def add_ip_policy(site_id: str, ip_cidr: str, action: str, reason: str = "") -> int:
    try:
        ipaddress.ip_network(ip_cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"잘못된 IP/CIDR: {ip_cidr}") from exc
    if action not in ("allow", "block"):
        raise ValueError("action은 'allow' 또는 'block' 이어야 합니다.")
    with _LOCK:
        conn = _ensure_conn()
        cur = conn.execute(
            "INSERT INTO ip_policies (site_id,ip_cidr,action,reason) VALUES (?,?,?,?)",
            (site_id, ip_cidr, action, reason),
        )
        conn.commit()
        return cur.lastrowid or 0


def delete_ip_policy(policy_id: int) -> None:
    with _LOCK:
        conn = _ensure_conn()
        conn.execute("DELETE FROM ip_policies WHERE id=?", (policy_id,))
        conn.commit()


def list_ip_policies(site_id: str) -> list[dict[str, Any]]:
    with _LOCK:
        conn = _ensure_conn()
        rows = conn.execute(
            "SELECT * FROM ip_policies WHERE site_id=? ORDER BY id", (site_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def add_audit_log(
    *, username: str, site_id: str, action: str,
    target: str = "", before: Any = None, after: Any = None, client_ip: str = "",
) -> None:
    with _LOCK:
        conn = _ensure_conn()
        conn.execute(
            "INSERT INTO audit_logs (username,site_id,action,target,before_json,after_json,client_ip)"
            " VALUES (?,?,?,?,?,?,?)",
            (
                username, site_id, action, target,
                json.dumps(before or {}, ensure_ascii=False, default=str),
                json.dumps(after or {}, ensure_ascii=False, default=str),
                client_ip,
            ),
        )
        conn.commit()


def list_audit_logs(site_id: "str | None" = None, limit: int = 100) -> list[dict[str, Any]]:
    with _LOCK:
        conn = _ensure_conn()
        if site_id:
            rows = conn.execute(
                "SELECT * FROM audit_logs WHERE site_id=? ORDER BY id DESC LIMIT ?",
                (site_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
    return [dict(r) for r in rows]


def record_request(
    *, site_id: str, domain: str, time_iso: str, client_ip: str, method: str,
    path: str, query_string: str, user_agent: str, status_code: int,
    detected: bool, blocked: bool, policy_mode: str, origin_url: str,
) -> int:
    with _LOCK:
        conn = _ensure_conn()
        cur = conn.execute(
            """INSERT INTO site_requests
               (site_id,domain,time_iso,client_ip,method,path,query_string,
                user_agent,status_code,detected,blocked,policy_mode,origin_url)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                site_id, domain, time_iso, client_ip, method, path,
                query_string, user_agent[:512], status_code,
                1 if detected else 0, 1 if blocked else 0, policy_mode, origin_url,
            ),
        )
        conn.commit()
        return cur.lastrowid or 0


def record_detection(
    *, request_id: int, site_id: str, owasp_id: str, rule_id: str,
    attack_type: str, severity: str, location: str, evidence: str, action: str,
) -> None:
    with _LOCK:
        conn = _ensure_conn()
        conn.execute(
            """INSERT INTO site_detections
               (request_id,site_id,owasp_id,rule_id,attack_type,severity,location,evidence,action)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (request_id, site_id, owasp_id, rule_id, attack_type, severity,
             location, evidence[:500], action),
        )
        conn.commit()


def get_site_stats(site_id: str, hours: int = 24) -> dict[str, Any]:
    with _LOCK:
        conn = _ensure_conn()
        total = conn.execute(
            "SELECT COUNT(*) FROM site_requests WHERE site_id=? AND time_iso>=datetime('now',?)",
            (site_id, f"-{hours} hours"),
        ).fetchone()[0]
        blocked = conn.execute(
            "SELECT COUNT(*) FROM site_requests WHERE site_id=? AND blocked=1 AND time_iso>=datetime('now',?)",
            (site_id, f"-{hours} hours"),
        ).fetchone()[0]
        detected = conn.execute(
            "SELECT COUNT(*) FROM site_requests WHERE site_id=? AND detected=1 AND time_iso>=datetime('now',?)",
            (site_id, f"-{hours} hours"),
        ).fetchone()[0]
        top_rules = conn.execute(
            "SELECT rule_id,COUNT(*) AS cnt FROM site_detections WHERE site_id=?"
            " GROUP BY rule_id ORDER BY cnt DESC LIMIT 5",
            (site_id,),
        ).fetchall()
    return {
        "site_id": site_id, "hours": hours,
        "total_requests": total, "blocked": blocked, "detected": detected,
        "top_rules": [{"rule_id": r["rule_id"], "count": r["cnt"]} for r in top_rules],
    }


def init() -> None:
    with _LOCK:
        _ensure_conn()
