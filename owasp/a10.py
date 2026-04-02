"""A10:2025 — Mishandling of Exceptional Conditions

예외 상황을 잘못 처리하여 스택 트레이스·내부 경로·DB 오류 등
민감 정보가 노출되거나 애플리케이션이 비정상 종료되는 취약점을 탐지한다.

관련 CWE: CWE-209, CWE-390, CWE-391, CWE-544, CWE-636, CWE-1321 등 24개

────────────────────────────────────────────────────────────────────────────────
Juice Shop 검증 시나리오 (요청만으로 탐지 가능한 패턴)
────────────────────────────────────────────────────────────────────────────────
Rule              | 탐지 내용                        | Juice Shop 호출 예시
──────────────────┼──────────────────────────────────┼─────────────────────────────────────────────
A10-UNDEF-001     | 'undefined' ID in URL path       | GET /api/Products/undefined
A10-UNDEF-002     | 'NaN'/'Infinity' ID in URL path  | GET /api/Users/NaN
A10-UNDEF-003     | 'null' ID in URL path            | GET /api/Products/null
A10-PROTO-001     | __proto__ 키 — 프로토타입 오염    | POST /api/* body: {"__proto__":{"isAdmin":true}}
A10-PROTO-002     | constructor.prototype 체인        | POST /api/* body: {"constructor":{"prototype":{}}}
A10-PROTO-003     | __defineGetter__/__defineSetter__ | POST body: {"__defineGetter__":"x"}
A10-BOUND-001     | JS MAX_SAFE_INTEGER 초과 ID       | GET /api/Products/9007199254740993
A10-BOUND-002     | 음수 정수 ID in URL path          | GET /api/Products/-1
A10-BOUND-003     | INT32 경계 값 (±2147483648)       | GET /api/Users/2147483648
A10-BOUND-004     | 0 as resource ID                 | GET /api/Products/0
A10-NULLB-001     | URL-encoded null byte (%00)       | GET /path%00.txt
A10-NULLB-002     | 리터럴 null byte in body          | POST body 내 \\x00
A10-NULLB-003     | Overlong UTF-8 null (%c0%80)      | GET /path%c0%80
A10-FMT-001       | Printf 형식 지정자 시퀀스          | POST body/query: %s%s%d%n
A10-FMT-002       | Node.js util.format 지정자        | query: %s%d%i%o
A10-DEEP-001      | JSON 중첩 깊이 ≥ 15 (스택 오버플로)| POST body: {"a":{"b":{...20 levels...}}}
A10-TYPECONF-001  | NoSQL 연산자를 스칼라 필드 값으로   | POST /rest/user/login {"email":{"$gt":""}}
A10-TYPECONF-002  | 인증 필드에 오브젝트 값 주입        | POST /login {"password":{"x":1}}
A10-TYPECONF-003  | 단일 오브젝트 기대 엔드포인트에 배열 | POST /api/* body: [...]
A10-ERRPRB-001    | 검색 쿼리 괄호 불균형 (SQLite FTS5) | GET /rest/products/search?q=)))
A10-ERRPRB-002    | ORM 오류 생성 함수 주입             | query: extractvalue(1,concat(...))
A10-ERRPRB-003    | 백업/디버그 파일 확장자 접근         | GET /app.js.bak
A10-HDRNOM-001    | 역순 Range 헤더 (end < start)      | Range: bytes=100-0
A10-HDRNOM-002    | 비정상적으로 큰 단일 헤더 값         | X-Custom: <8KB+>
────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import html
import json
import math
import re
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from typing import Any

from owasp.types import Finding, ModuleScanResult, RequestContext, Severity


# ── 모듈 메타데이터 ──────────────────────────────────────────────────────────

MODULE_ID = "a10"
OWASP_ID  = "A10:2025"
TITLE     = "Mishandling of Exceptional Conditions"


# ── Shannon Entropy & 점수 계산 ──────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _entropy_bonus(entropy: float) -> float:
    """고엔트로피(난독화/무작위) 페이로드에 추가 점수."""
    if entropy >= 4.5:
        return 0.5
    if entropy >= 3.5:
        return 0.25
    return 0.0


def _score_to_severity(score: float) -> Severity:
    if score >= 3.5:
        return Severity.CRITICAL
    if score >= 2.5:
        return Severity.HIGH
    if score >= 1.5:
        return Severity.MEDIUM
    return Severity.LOW


# ── 규칙 데이터클래스 ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class _Rule:
    rule_id:     str
    description: str
    base_score:  float
    pattern:     re.Pattern[str] | None = None


# ── 카테고리 레이블 ──────────────────────────────────────────────────────────

_CATEGORY_LABEL: dict[str, str] = {
    "UNDEF":    "Undefined Identifier",
    "PROTO":    "Prototype Pollution",
    "BOUND":    "Boundary / Integer Overflow",
    "NULLB":    "Null-Byte Injection",
    "FMT":      "Format String Probe",
    "DEEP":     "Deep Nesting / DoS",
    "TYPECONF": "Type Confusion",
    "ERRPRB":   "Error Probe",
    "HDRNOM":   "Header Anomaly",
}


def _category_label(rule_id: str) -> str:
    """'A10-UNDEF-001' → 'Undefined Identifier'"""
    parts = rule_id.split("-")
    if len(parts) >= 3:
        return _CATEGORY_LABEL.get(parts[1], parts[1])
    return rule_id


# ── 규칙 목록 ────────────────────────────────────────────────────────────────

# ─── UNDEF: JS 런타임 식별자를 리소스 ID로 사용 ──────────────────────────────
# Juice Shop: GET /api/Products/undefined → Node.js TypeError (unhandled)
_UNDEF_RULES: list[_Rule] = [
    _Rule(
        "A10-UNDEF-001",
        "'undefined'를 리소스 ID로 사용 — Node.js TypeError 유발 (CWE-391)",
        base_score=2.5,
        pattern=re.compile(r"(?:^|/)undefined(?:/|$)", re.IGNORECASE),
    ),
    _Rule(
        "A10-UNDEF-002",
        "'NaN' 또는 'Infinity'를 리소스 ID로 사용 — 수치 강제 변환 실패 (CWE-390)",
        base_score=2.5,
        pattern=re.compile(r"(?:^|/)(?:NaN|-?Infinity)(?:/|$)", re.IGNORECASE),
    ),
    _Rule(
        "A10-UNDEF-003",
        "'null'을 리소스 ID로 사용 — Null 포인터 참조 예외 (CWE-476)",
        base_score=2.0,
        pattern=re.compile(r"(?:^|/)null(?:/|$)", re.IGNORECASE),
    ),
]

# ─── PROTO: 프로토타입 오염 (Node.js / JavaScript) ───────────────────────────
# Juice Shop: POST /api/* body {"__proto__":{"isAdmin":true}} → crash or priv-esc
_PROTO_RULES: list[_Rule] = [
    _Rule(
        "A10-PROTO-001",
        "__proto__ 키 주입 — JavaScript 프로토타입 오염 (CWE-1321)",
        base_score=3.5,
        pattern=re.compile(r"__proto__"),
    ),
    _Rule(
        "A10-PROTO-002",
        "constructor.prototype 체인 조작 — JS 표기법과 JSON 키 중첩 모두 탐지 (CWE-1321)",
        base_score=3.5,
        # JS: constructor.prototype  /  JSON: "constructor":{"prototype":...}
        pattern=re.compile(
            r'constructor\s*[.\[]\s*prototype'
            r'|"constructor"\s*:\s*\{[^}]{0,100}"prototype"',
        ),
    ),
    _Rule(
        "A10-PROTO-003",
        "__defineGetter__/__defineSetter__ — 레거시 프로토타입 재정의 (CWE-1321)",
        base_score=3.0,
        pattern=re.compile(r"__define(?:Getter|Setter)__"),
    ),
]

# ─── BOUND: 경계값 / 정수 오버플로 ──────────────────────────────────────────
# Juice Shop: GET /api/Products/-1, /api/Products/9007199254740993
_BOUND_PATH_RULES: list[_Rule] = [
    _Rule(
        "A10-BOUND-001",
        "JS MAX_SAFE_INTEGER(2^53) 초과 ID — 정수 정밀도 손실, ORM 오류 (CWE-190)",
        base_score=2.5,
        pattern=re.compile(r"(?:^|/)(?:9007199254740(?:99[3-9]|\d{4,})|\d{17,})(?:/|$)"),
    ),
    _Rule(
        "A10-BOUND-002",
        "음수 정수 리소스 ID — ORM '행 없음' 예외 미처리 (CWE-391)",
        base_score=2.0,
        pattern=re.compile(r"(?:^|/)-[1-9]\d*(?:/|$)"),
    ),
    _Rule(
        "A10-BOUND-003",
        "INT32 경계값(±2147483647/2147483648) — 부호 오버플로 (CWE-190)",
        base_score=2.5,
        pattern=re.compile(r"(?:^|/)(?:2147483648|2147483647|4294967295|4294967296)(?:/|$)"),
    ),
    _Rule(
        "A10-BOUND-004",
        "0을 리소스 ID로 사용 — ORM 결과 없음 미처리 예외 (CWE-391)",
        base_score=1.5,
        pattern=re.compile(r"(?:/api/|/rest/)[^/?#]+/0(?:/|$|\?)"),
    ),
]

# ─── NULLB: Null 바이트 주입 ─────────────────────────────────────────────────
_NULLB_RULES: list[_Rule] = [
    _Rule(
        "A10-NULLB-001",
        "URL 인코딩된 null 바이트(%00) — C 문자열 종료, 검증 우회 (CWE-626)",
        base_score=2.5,
        pattern=re.compile(r"%00", re.IGNORECASE),
    ),
    _Rule(
        "A10-NULLB-002",
        "리터럴 null 바이트(\\x00) in body — 파서 크래시, 문자열 경계 위반 (CWE-626)",
        base_score=2.5,
        pattern=re.compile(r"\x00"),
    ),
    _Rule(
        "A10-NULLB-003",
        "Overlong UTF-8 null 인코딩(%c0%80) — 유니코드 우회 공격 (CWE-116)",
        base_score=2.5,
        pattern=re.compile(r"%c0%80", re.IGNORECASE),
    ),
]

# ─── FMT: 형식 문자열 프로브 ─────────────────────────────────────────────────
_FMT_RULES: list[_Rule] = [
    _Rule(
        "A10-FMT-001",
        "Printf 형식 지정자 연속(%s%d%n%x) — C/C++ 백엔드 메모리 누출·크래시 (CWE-134)",
        base_score=2.0,
        pattern=re.compile(r"(?:%[sdnxXpoufeEgGi]){2,}"),
    ),
    _Rule(
        "A10-FMT-002",
        "Node.js util.format 지정자 연속(%s%d%i%o) — 민감 정보 로그 인젝션 (CWE-117)",
        base_score=1.5,
        pattern=re.compile(r"(?:%[sdiojO]\s*){3,}"),
    ),
]

# ─── TYPECONF: 타입 혼동 공격 ────────────────────────────────────────────────
# Juice Shop: POST /rest/user/login {"email":{"$gt":""},"password":""}
_TYPECONF_BODY_RULES: list[_Rule] = [
    _Rule(
        "A10-TYPECONF-001",
        "NoSQL 연산자를 스칼라 필드 값으로 주입({\"$gt\":\"\"}) — Sequelize 타입 불일치 크래시 (CWE-843)",
        base_score=3.0,
        pattern=re.compile(
            r'"\s*:\s*\{\s*"\$(?:gt|lt|gte|lte|ne|eq|in|nin|exists|regex|where)\b',
            re.IGNORECASE,
        ),
    ),
    _Rule(
        "A10-TYPECONF-002",
        "인증 필드에 오브젝트 주입({\"password\":{...}}) — 로그인 핸들러 타입 강제 변환 예외 (CWE-843)",
        base_score=2.5,
        pattern=re.compile(
            r'"(?:password|passwd|username|email|login|token|id|userId|user_id)"\s*:\s*\{',
        ),
    ),
]

# ─── ERRPRB: 오류 프로브 / 알려진 크래시 트리거 ──────────────────────────────
# Juice Shop: GET /rest/products/search?q=))) → SQLite FTS5 파서 오류
_ERRPRB_SEARCH_RULES: list[_Rule] = [
    _Rule(
        "A10-ERRPRB-001",
        "검색 쿼리 내 괄호 불균형 — SQLite FTS5 파서 오류 → Sequelize 미처리 예외 (CWE-391)",
        base_score=2.5,
        pattern=re.compile(r"\){2,}|\({2,}"),
    ),
    _Rule(
        "A10-ERRPRB-002",
        "ORM 오류 생성 함수 주입(extractvalue/updatexml) — DB 오류 메시지 정보 노출 (CWE-209)",
        base_score=2.5,
        pattern=re.compile(r"extractvalue\s*\(|updatexml\s*\(|exp\s*\(\s*~", re.IGNORECASE),
    ),
]

_ERRPRB_PATH_RULES: list[_Rule] = [
    _Rule(
        "A10-ERRPRB-003",
        "백업/디버그 파일 확장자 접근 — 핸들러 없음 → 500 또는 소스 노출 (CWE-209)",
        base_score=2.0,
        pattern=re.compile(
            r"\.(?:bak|backup|orig|old|save|swp|tmp|temp|sql|dump|log)$",
            re.IGNORECASE,
        ),
    ),
]


# ── 프로그래밍 방식 검사 ─────────────────────────────────────────────────────

def _json_max_depth(obj: Any, current: int = 0) -> int:
    """JSON 오브젝트의 최대 중첩 깊이를 재귀적으로 계산한다."""
    if isinstance(obj, dict):
        if not obj:
            return current
        return max(_json_max_depth(v, current + 1) for v in obj.values())
    if isinstance(obj, list):
        if not obj:
            return current
        return max(_json_max_depth(item, current + 1) for item in obj)
    return current


def _check_json_depth(body: str, location: str) -> Finding | None:
    """JSON 중첩 깊이 ≥ 15 이면 Finding 반환 (스택 오버플로/DoS 위험)."""
    stripped = body.strip()
    if not stripped or stripped[0] not in ("{", "["):
        return None
    try:
        obj = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return None
    depth = _json_max_depth(obj)
    if depth < 15:
        return None
    if depth >= 30:
        score = 4.0
    elif depth >= 20:
        score = 3.0
    else:
        score = 2.0
    return Finding(
        rule_id="A10-DEEP-001",
        evidence=f"JSON 중첩 깊이={depth} (임계값=15)",
        severity=_score_to_severity(score),
        location=f"{location} — Deep Nesting / DoS",
    )


def _check_json_array_root(body: str, location: str) -> Finding | None:
    """단일 오브젝트 예상 엔드포인트에 배열이 전달된 경우 Finding 반환."""
    stripped = body.strip()
    if not stripped or stripped[0] != "[":
        return None
    try:
        obj = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(obj, list):
        return None
    return Finding(
        rule_id="A10-TYPECONF-003",
        evidence=f"JSON 루트가 배열 (길이={len(obj)}) — 오브젝트 기대",
        severity=Severity.LOW,
        location=f"{location} — Type Confusion",
    )


def _check_range_header(value: str, location: str) -> Finding | None:
    """Range: bytes=end-start 처럼 end < start 인 역순 Range 헤더 탐지."""
    m = re.match(r"bytes\s*=\s*(\d+)\s*-\s*(\d+)", value, re.IGNORECASE)
    if not m:
        return None
    start, end = int(m.group(1)), int(m.group(2))
    if end < start:
        return Finding(
            rule_id="A10-HDRNOM-001",
            evidence=f"Range: {value} (end={end} < start={start})",
            severity=_score_to_severity(2.0),
            location=f"{location} — Header Anomaly",
        )
    return None


def _check_oversized_header(headers: dict[str, str]) -> Finding | None:
    """단일 헤더 값이 8 KB 초과인 경우 탐지 (헤더 버퍼 오버플로)."""
    for key, val in headers.items():
        if len(val) > 8192:
            score = 2.5 if len(val) >= 16384 else 2.0
            return Finding(
                rule_id="A10-HDRNOM-002",
                evidence=f"헤더 '{key}' 크기={len(val)} bytes (임계값=8192)",
                severity=_score_to_severity(score),
                location=f"header:{key} — Header Anomaly",
            )
    return None


# ── 공통 규칙 적용 헬퍼 ──────────────────────────────────────────────────────

def _apply_rules(
    value: str,
    location: str,
    rules: list[_Rule],
    *,
    max_evidence: int = 120,
) -> list[Finding]:
    """주어진 규칙 목록을 value에 적용하여 Finding 목록을 반환한다."""
    out: list[Finding] = []
    seen: set[str] = set()
    for rule in rules:
        if rule.pattern is None:
            continue
        if not rule.pattern.search(value):
            continue
        if rule.rule_id in seen:
            continue
        seen.add(rule.rule_id)
        entropy = _shannon_entropy(value)
        score   = rule.base_score + _entropy_bonus(entropy)
        sev     = _score_to_severity(score)
        evid    = value[:max_evidence] + ("…" if len(value) > max_evidence else "")
        cat     = _category_label(rule.rule_id)
        out.append(
            Finding(
                rule_id=rule.rule_id,
                evidence=evid,
                severity=sev,
                location=f"{location} — {cat}",
            )
        )
    return out


# ── 중복 제거: rule_id 당 가장 심각도 높은 Finding 1개 ────────────────────────

_SEV_RANK: dict[Severity, int] = {
    Severity.NONE:     0,
    Severity.LOW:      1,
    Severity.MEDIUM:   2,
    Severity.HIGH:     3,
    Severity.CRITICAL: 4,
}


def _deduplicate(findings: list[Finding]) -> tuple[Finding, ...]:
    best: dict[str, Finding] = {}
    for f in findings:
        prev = best.get(f.rule_id)
        if prev is None or _SEV_RANK[f.severity] > _SEV_RANK[prev.severity]:
            best[f.rule_id] = f
    return tuple(best.values())


# ── 메인 스캔 엔트리 포인트 ──────────────────────────────────────────────────

async def scan(ctx: RequestContext) -> ModuleScanResult:
    """A10:2025 Mishandling of Exceptional Conditions 탐지.

    스캔 범위:
      · URL 경로 (UNDEF, BOUND, ERRPRB, NULLB)
      · 쿼리 파라미터 (UNDEF, NULLB, FMT, ERRPRB, PROTO)
      · 요청 바디 (PROTO, FMT, TYPECONF, NULLB, DEEP)
      · HTTP 헤더 (HDRNOM)
    """
    findings: list[Finding] = []

    raw_path   = ctx.path
    raw_query  = ctx.query_string
    body       = ctx.body_preview
    headers_lc = {k.lower(): v for k, v in ctx.headers.items()}

    decoded_path  = urllib.parse.unquote(raw_path)
    decoded_query = urllib.parse.unquote(raw_query)
    query_params  = urllib.parse.parse_qsl(raw_query, keep_blank_values=True)

    # ── 1. UNDEF: path 세그먼트 + 쿼리 파라미터 값 ───────────────────────────
    findings.extend(_apply_rules(decoded_path, "path", _UNDEF_RULES))
    for param, val in query_params:
        dv = urllib.parse.unquote(val)
        findings.extend(_apply_rules(dv, f"query.{param}", _UNDEF_RULES))

    # ── 2. PROTO: body + 전체 쿼리 문자열 ────────────────────────────────────
    findings.extend(_apply_rules(body, "body", _PROTO_RULES))
    findings.extend(_apply_rules(decoded_query, "query", _PROTO_RULES))
    # 쿼리 키/값 개별 검사
    for param, val in query_params:
        dp = urllib.parse.unquote(param)
        dv = urllib.parse.unquote(val)
        findings.extend(_apply_rules(dp, f"query.{param}[key]", _PROTO_RULES))
        findings.extend(_apply_rules(dv, f"query.{param}", _PROTO_RULES))

    # ── 3. BOUND: path 세그먼트 ──────────────────────────────────────────────
    findings.extend(_apply_rules(decoded_path, "path", _BOUND_PATH_RULES))

    # ── 4. NULLB: raw path, raw query, body ──────────────────────────────────
    findings.extend(_apply_rules(raw_path,     "path",  _NULLB_RULES))
    findings.extend(_apply_rules(raw_query,    "query", _NULLB_RULES))
    findings.extend(_apply_rules(body,         "body",  _NULLB_RULES))

    # ── 5. FMT: query 파라미터 값 + body ─────────────────────────────────────
    for param, val in query_params:
        dv = urllib.parse.unquote(val)
        findings.extend(_apply_rules(dv, f"query.{param}", _FMT_RULES))
    findings.extend(_apply_rules(body, "body", _FMT_RULES))

    # ── 6. DEEP: JSON body 중첩 깊이 ─────────────────────────────────────────
    if body.strip()[:1] in ("{", "["):
        depth_f = _check_json_depth(body, "body")
        if depth_f:
            findings.append(depth_f)

    # ── 7. TYPECONF: JSON body 타입 혼동 ─────────────────────────────────────
    ct = headers_lc.get("content-type", "")
    if "json" in ct or body.strip()[:1] in ("{", "["):
        findings.extend(_apply_rules(body, "body", _TYPECONF_BODY_RULES))
        arr_f = _check_json_array_root(body, "body")
        if arr_f:
            findings.append(arr_f)

    # ── 8. ERRPRB: 검색 파라미터 + path + body ────────────────────────────────
    _SEARCH_PARAMS = frozenset({"q", "search", "query", "s", "term", "keyword", "filter"})
    for param, val in query_params:
        dv = urllib.parse.unquote(val)
        if param.lower() in _SEARCH_PARAMS or "/search" in decoded_path.lower():
            findings.extend(_apply_rules(dv, f"query.{param}", _ERRPRB_SEARCH_RULES))
        else:
            # ERRPRB-002 (ORM 크래시 함수)는 모든 파라미터에 적용
            findings.extend(_apply_rules(dv, f"query.{param}", [_ERRPRB_SEARCH_RULES[1]]))
    findings.extend(_apply_rules(decoded_path, "path",  _ERRPRB_PATH_RULES))
    findings.extend(_apply_rules(body,         "body",  [_ERRPRB_SEARCH_RULES[1]]))

    # ── 9. HDRNOM: HTTP 헤더 이상 ─────────────────────────────────────────────
    range_val = headers_lc.get("range", "")
    if range_val:
        rf = _check_range_header(range_val, "header:Range")
        if rf:
            findings.append(rf)

    oversized_f = _check_oversized_header(ctx.headers)
    if oversized_f:
        findings.append(oversized_f)

    return ModuleScanResult(
        module_id=MODULE_ID,
        owasp_id=OWASP_ID,
        findings=_deduplicate(findings),
    )


# ── 독립 테스트용 블록 HTML 생성 ─────────────────────────────────────────────

def make_block_html(result: ModuleScanResult) -> str:
    """탐지 결과를 HTML 차단 페이지로 렌더링 (standalone 테스트용)."""
    if not result.findings:
        return "<p>탐지된 패턴 없음</p>"

    _SEV_COLOR = {
        "critical": "#c0392b",
        "high":     "#e67e22",
        "medium":   "#f1c40f",
        "low":      "#27ae60",
        "none":     "#95a5a6",
    }
    _SEV_KO = {
        "critical": "크리티컬",
        "high":     "하이",
        "medium":   "미디엄",
        "low":      "로우",
    }

    top: Finding = max(result.findings, key=lambda f: _SEV_RANK[f.severity])
    sev_val = top.severity.value
    color   = _SEV_COLOR.get(sev_val, "#95a5a6")
    sev_ko  = _SEV_KO.get(sev_val, sev_val.upper())
    cat_label = _category_label(top.rule_id)

    rows_html = ""
    for f in sorted(result.findings, key=lambda x: _SEV_RANK[x.severity], reverse=True):
        fcolor = _SEV_COLOR.get(f.severity.value, "#95a5a6")
        fko    = _SEV_KO.get(f.severity.value, f.severity.value)
        rows_html += f"""
      <tr>
        <td><code>{html.escape(f.rule_id)}</code></td>
        <td>{html.escape(f.location or '—')}</td>
        <td><span style="color:{fcolor};font-weight:bold">{fko}</span></td>
        <td style="font-size:0.85em;word-break:break-all">{html.escape(f.evidence[:100])}</td>
      </tr>"""

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <title>WAF 차단 — A10:2025</title>
  <style>
    body{{font-family:'Segoe UI',sans-serif;background:#1a1a2e;color:#eee;margin:0;display:flex;
          justify-content:center;align-items:center;min-height:100vh}}
    .card{{background:#16213e;border:2px solid {color};border-radius:12px;padding:2rem 2.5rem;
           max-width:860px;width:100%;box-shadow:0 0 30px {color}55}}
    h1{{color:{color};margin:0 0 0.4rem}}
    .badge{{display:inline-block;background:{color};color:#fff;
            border-radius:6px;padding:2px 10px;font-size:.85rem;margin-bottom:1rem}}
    table{{width:100%;border-collapse:collapse;margin-top:1rem;font-size:.9rem}}
    th{{background:#0f3460;padding:8px 10px;text-align:left}}
    td{{padding:7px 10px;border-bottom:1px solid #2a2a4a}}
    .footer{{margin-top:1.5rem;font-size:.8rem;color:#aaa}}
    .back{{display:inline-block;margin-top:1rem;padding:8px 18px;background:{color};
           color:#fff;border-radius:6px;text-decoration:none}}
  </style>
</head>
<body>
  <div class="card">
    <h1>🚫 WAF 차단 — {html.escape(OWASP_ID)}</h1>
    <span class="badge">{html.escape(sev_ko)} · {html.escape(cat_label)}</span>
    <p><strong>{html.escape(top.rule_id)}</strong>: {html.escape(_CATEGORY_LABEL.get(top.rule_id.split('-')[1] if len(top.rule_id.split('-'))>1 else '', top.rule_id))}</p>
    <table>
      <tr><th>규칙 ID</th><th>탐지 위치</th><th>심각도</th><th>증거 (일부)</th></tr>
      {rows_html}
    </table>
    <p class="footer">
      OWASP {html.escape(OWASP_ID)} — Mishandling of Exceptional Conditions<br>
      예외 조건을 유발하는 입력 패턴이 탐지되어 차단되었습니다.<br>
      정상 요청이라면 관리자에게 문의하세요.
    </p>
    <a class="back" href="javascript:history.back()">← 이전 페이지로</a>
  </div>
</body>
</html>"""
