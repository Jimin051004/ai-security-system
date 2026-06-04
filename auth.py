"""사용자 인증 모듈 — WAF 대시보드 로그인 계정 관리.

waf_auth.sqlite3 에 users 테이블을 관리하며,
PBKDF2-SHA256 으로 비밀번호를 해시합니다.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_AUTH_DB_PATH = str(Path(__file__).resolve().parent / "waf_auth.sqlite3")
AUTH_DB_PATH = _AUTH_DB_PATH  # 진단·부트 메타와 공유 경로 참조용
_LOCK = threading.Lock()
_conn: sqlite3.Connection | None = None

# 다중 프로세스(중앙 대시보드 + 프록시 동시 기동 등) SQLite 잠금 완화
_DB_LOCK_RETRIES = 25
_DB_LOCK_SLEEP_SEC = 0.15

# 회원가입 시 사용 불가 (다른 테넌트와 충돌·혼동 방지)
_RESERVED_SITE_IDS = frozenset(
    {
        "admin",
        "default",
        "all",
        "global",
        "system",
        "public",
        "new",
        "test",
        "root",
        "",
    }
)


_IPV4_COLON_PORT = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::(\d{1,5}))?$"
)
_DOMAIN_WITH_TLD_OR_PORT = re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:\d{1,5})?$",
)


def _ensure_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(_AUTH_DB_PATH, check_same_thread=False, timeout=120)
        _conn.execute("PRAGMA busy_timeout = 60000")
        _conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                site_id TEXT NOT NULL DEFAULT '',
                sensor_token TEXT NOT NULL DEFAULT '',
                is_admin INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        _conn.commit()
        try:
            _conn.execute("ALTER TABLE users ADD COLUMN sensor_token TEXT NOT NULL DEFAULT ''")
            _conn.commit()
        except sqlite3.DatabaseError:
            pass
        try:
            _conn.execute(
                "UPDATE users SET sensor_token = ? || lower(hex(randomblob(16))) WHERE sensor_token = ''",
                ("sensor_",),
            )
            _conn.commit()
        except sqlite3.DatabaseError:
            pass
        try:
            _conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_site
                ON users(site_id COLLATE NOCASE)
                WHERE is_admin = 0 AND length(trim(site_id)) > 0
                """
            )
            _conn.commit()
        except sqlite3.DatabaseError:
            pass
        try:
            _conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_users_sensor_token
                ON users(sensor_token)
                WHERE length(trim(sensor_token)) > 0
                """
            )
            _conn.commit()
        except sqlite3.DatabaseError:
            pass
    return _conn


def _new_sensor_token() -> str:
    return "sensor_" + secrets.token_urlsafe(32)


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 260_000
    ).hex()


def normalize_site_id(raw: str) -> str:
    """소문자·하이픈 정규화. 영문/숫자/하이픈/밑줄만 유지."""
    s = raw.strip().lower()
    s = re.sub(r"[\s_]+", "-", s)
    s = re.sub(r"[^a-z0-9_-]+", "", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s


def is_site_id_taken(site_id: str) -> bool:
    """일반 사용자 중 동일 site_id(대소문자 무시)가 있으면 True."""
    sid = normalize_site_id(site_id)
    if not sid:
        return True
    with _LOCK:
        conn = _ensure_conn()
        row = conn.execute(
            """
            SELECT 1 FROM users
            WHERE is_admin = 0 AND length(trim(site_id)) > 0
              AND lower(trim(site_id)) = lower(?)
            """,
            (sid,),
        ).fetchone()
    return row is not None


def _looks_hostish_for_derived_site_id(pre: str) -> bool:
    """예: Juice Shop URL처럼 IP/호스트 형태만 URL에서 SITE_ID 추론한다."""
    s = pre.strip().rstrip(".")
    if not s:
        return False
    if s.startswith("[") and "]" in s:
        # [::1]:3000 등 브래킷 IPv6 — urlparse로만 안전 처리 (SITE_ID 추론은 IPv4/도메인용)
        return True
    if _DOMAIN_WITH_TLD_OR_PORT.fullmatch(s):
        return True
    if _IPV4_COLON_PORT.fullmatch(s):
        return True
    if ":" in s:
        left, sep, right = s.rpartition(":")
        if sep and left and right.isdigit() and 1 <= int(right) <= 65535:
            return True
    return False


def _slug_from_hostname_port(hostname: str, port: int | None) -> str:
    hn = hostname.strip().strip(".").lower()
    if not hn or "%" in hn:
        raise ValueError("host")
    try:
        ip = ipaddress.ip_address(hn)
    except ValueError:
        slug = hn.replace(".", "-")
    else:
        if isinstance(ip, ipaddress.IPv6Address):
            raise ValueError("ipv6")
        slug = "-".join(hn.split("."))
    if port is not None and port >= 1:
        slug = f"{slug}-p-{port}"
    return slug


def registration_resolve_site_id(raw: str) -> tuple[str | None, str | None]:
    """
    회원가입 필드: 짧은 사이트 ID 또는 http(s)://호스트:포트 (Juice Shop 주소) 수용.
    URL이면 호스트·포트로부터 결정적 슬러그를 만든다. 성공 시 (site_id, None).
    """
    trimmed = (raw or "").strip()
    if not trimmed:
        return None, "사이트 ID 또는 사이트 URL을 입력하세요."

    derive = False
    if "://" in trimmed:
        derive = True
    else:
        head = trimmed.split("#", 1)[0].split("?", 1)[0].split("/", 1)[0]
        if _looks_hostish_for_derived_site_id(head):
            derive = True

    if derive:
        url_probe = trimmed.split("#", 1)[0].split("?", 1)[0]
        if "://" not in url_probe:
            head = url_probe.split("/", 1)[0]
            url_probe = "http://" + head
        try:
            p = urlparse(url_probe)
            hostname = p.hostname
        except ValueError:
            return None, "주소 형식이 올바르지 않습니다. IPv6는 사이트 ID를 직접 입력해 주세요."
        try:
            iport = p.port
        except ValueError:
            return None, (
                "주소에 포트를 해석할 수 없습니다. "
                "IPv6는 사이트 ID를 직접 입력해 주세요 (예: team-lab-1)."
            )
        if not hostname:
            return None, "URL을 해석할 수 없습니다. 예: http://192.168.1.10:3000"
        try:
            slug = _slug_from_hostname_port(hostname, iport)
        except ValueError:
            return None, "IPv6 등은 사이트 ID를 직접 입력해 주세요 (예: team-lab-1)."
        sid = normalize_site_id(slug)
    else:
        sid = normalize_site_id(trimmed)

    if len(sid) < 2 or len(sid) > 48:
        return None, "사이트 ID는 2~48자(정규화 후)여야 합니다."
    if not re.match(r"^[a-z0-9][a-z0-9_-]*$", sid):
        return None, "사이트 ID는 소문자·숫자로 시작하고, 영문 소문자·숫자·-·_ 만 사용하세요."
    if sid in _RESERVED_SITE_IDS:
        return None, "사용할 수 없는 사이트 ID입니다. 다른 값을 입력하세요."
    return sid, None


def _validate_public_registration(
    username: str,
    password: str,
    password_confirm: str,
    site_id_normalized: str,
) -> str | None:
    u = username.strip()
    if len(u) < 3 or len(u) > 32:
        return "아이디는 3~32자여야 합니다."
    if not re.match(r"^[a-zA-Z0-9_-]+$", u):
        return "아이디는 영문, 숫자, _, - 만 사용할 수 있습니다."
    if password != password_confirm:
        return "비밀번호가 서로 일치하지 않습니다."
    if len(password) < 8:
        return "비밀번호는 8자 이상이어야 합니다."
    # site_id는 registration_resolve_site_id 로 이미 정규화·검증됨
    if not site_id_normalized:
        return "사이트 ID가 비어 있습니다."
    return None


def register_public_user(
    username: str,
    password: str,
    password_confirm: str,
    site_id_raw: str,
) -> tuple[bool, str, str]:
    """
    공개 회원가입. 성공 시 (True, "", 등록된 site_id), 실패 시 (False, 메시지, "").
    site_id_raw는 짧은 ID 또는 Juice Shop URL(http://IP:3000/ 등)을 넣을 수 있다.
    """
    sid, field_err = registration_resolve_site_id(site_id_raw)
    if field_err:
        return False, field_err, ""
    err = _validate_public_registration(
        username, password, password_confirm, sid
    )
    if err:
        return False, err, ""
    if is_site_id_taken(sid):
        return False, "이미 등록된 사이트 ID입니다. 다른 사이트 ID를 선택하세요.", ""
    if not create_user(username.strip(), password, site_id=sid, is_admin=False):
        return False, "이미 사용 중인 아이디이거나 다른 계정에 등록된 사이트 ID입니다.", ""
    return True, "", sid


def create_user(
    username: str,
    password: str,
    site_id: str = "",
    is_admin: bool = False,
) -> bool:
    """신규 사용자를 생성합니다. 이미 존재하면 False 반환."""
    if not username or not password:
        return False
    salt = os.urandom(16).hex()
    pw_hash = f"{salt}:{_hash_password(password, salt)}"
    sensor_token = _new_sensor_token()
    params = (
        username.strip(),
        pw_hash,
        site_id.strip(),
        sensor_token,
        1 if is_admin else 0,
    )
    sql = """
        INSERT INTO users (username, password_hash, site_id, sensor_token, is_admin)
        VALUES (?,?,?,?,?)
    """
    last_exc: sqlite3.OperationalError | None = None
    for attempt in range(_DB_LOCK_RETRIES):
        with _LOCK:
            conn = _ensure_conn()
            try:
                conn.execute(sql, params)
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                conn.rollback()
                return False
            except sqlite3.OperationalError as exc:
                last_exc = exc
                try:
                    conn.rollback()
                except Exception:
                    pass
                msg = str(exc).lower()
                if "locked" in msg or "busy" in msg:
                    pass
                else:
                    raise
        time.sleep(_DB_LOCK_SLEEP_SEC * min(attempt + 1, 10))
    if last_exc:
        raise last_exc
    return False


def verify_user(username: str, password: str) -> dict[str, Any] | None:
    """사용자 인증. 성공하면 user dict 반환, 실패하면 None."""
    if not username or not password:
        return None
    with _LOCK:
        conn = _ensure_conn()
        row = conn.execute(
            "SELECT username, password_hash, site_id, is_admin FROM users WHERE username = ?",
            (username.strip(),),
        ).fetchone()
    if row is None:
        return None
    stored = row[1]
    if ":" not in stored:
        return None
    salt, stored_hash = stored.split(":", 1)
    if _hash_password(password, salt) != stored_hash:
        return None
    return {
        "username": str(row[0]),
        "site_id": str(row[2]),
        "is_admin": bool(row[3]),
    }


def get_sensor_config_for_username(username: str) -> dict[str, str] | None:
    """로그인 사용자에게 보여줄 센서 연결 정보."""
    with _LOCK:
        conn = _ensure_conn()
        row = conn.execute(
            """
            SELECT username, site_id, sensor_token, is_admin
            FROM users
            WHERE username = ?
            """,
            (username.strip(),),
        ).fetchone()
        if row is not None and not str(row[2] or ""):
            token = _new_sensor_token()
            conn.execute(
                "UPDATE users SET sensor_token = ? WHERE username = ?",
                (token, username.strip()),
            )
            conn.commit()
            row = (row[0], row[1], token, row[3])
    if row is None:
        return None
    return {
        "username": str(row[0]),
        "site_id": str(row[1] or ""),
        "sensor_token": str(row[2] or ""),
        "is_admin": bool(row[3]),
    }


def verify_sensor_token(site_id: str, sensor_token: str) -> bool:
    """센서 로그 수신 API 검증.

    - 일반 사용자: site_id 와(sensor_token 매칭) 동일해야 함.
    - 관리자: 동일 계정(auth)에서 발급된 sensor_token 이면 site_id 신뢰(프록시 SITE_ID 라벨).
      (기존에는 is_admin=0 만 허용해 admin 토큰으로는 ingest 가 항상 403 이었음)
    """
    sid = normalize_site_id(site_id)
    token = sensor_token.strip()
    if not sid or not token:
        return False
    with _LOCK:
        conn = _ensure_conn()
        admin_ok = conn.execute(
            """
            SELECT 1 FROM users
            WHERE is_admin = 1 AND trim(sensor_token) = ?
            """,
            (token,),
        ).fetchone()
        if admin_ok:
            return True
        row = conn.execute(
            """
            SELECT 1 FROM users
            WHERE is_admin = 0
              AND lower(trim(site_id)) = lower(?)
              AND sensor_token = ?
            """,
            (sid, token),
        ).fetchone()
    return row is not None


def get_all_users() -> list[dict[str, Any]]:
    """등록된 모든 사용자 목록 반환 (비밀번호 해시 제외)."""
    with _LOCK:
        conn = _ensure_conn()
        rows = conn.execute(
            "SELECT username, site_id, is_admin, created_at FROM users ORDER BY id"
        ).fetchall()
    return [
        {
            "username": r[0],
            "site_id": r[1],
            "is_admin": bool(r[2]),
            "created_at": r[3],
        }
        for r in rows
    ]


def delete_user(username: str) -> bool:
    """사용자 삭제. admin 계정은 삭제 불가."""
    if username == "admin":
        return False
    with _LOCK:
        conn = _ensure_conn()
        cur = conn.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        return cur.rowcount > 0


def ensure_default_users() -> None:
    """로컬/데모용 기본 계정. 운영에서는 WAF_SEED_DEFAULT_USERS=false 권장."""
    raw = os.environ.get("WAF_SEED_DEFAULT_USERS", "true").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return
    try:
        create_user("admin", "admin", site_id="", is_admin=True)
        create_user("jimin", "jimin", site_id="juiceshop", is_admin=False)
    except sqlite3.OperationalError:
        # 대시보드·프록시가 동시에 기동하면 waf_auth 잠금이 겹칠 수 있음(다른 프로세스가 이미 초기화)
        return
