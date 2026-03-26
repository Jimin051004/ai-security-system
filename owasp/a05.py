"""A05:2025 — Injection

프록시 레이어에서 업스트림 전달 전에 탐지한다.
검사 대상: URL 경로, 쿼리스트링, 요청 바디(미리보기), 주요 헤더
탐지 유형: SQL Injection, OS Command Injection, XSS,
           LDAP/XPath Injection, Expression Language Injection, CRLF Injection
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Sequence

from owasp.types import Finding, ModuleScanResult, RequestContext, Severity

OWASP_ID = "A05:2025"
MODULE_ID = "a05"
TITLE = "Injection"

# ---------------------------------------------------------------------------
# 검사할 헤더 목록 (값에 페이로드가 삽입될 수 있는 헤더)
# ---------------------------------------------------------------------------
_SCANNABLE_HEADERS = {
    "user-agent",
    "referer",
    "cookie",
    "x-forwarded-for",
    "x-real-ip",
    "x-custom-header",
    "accept-language",
    "origin",
    "content-type",
}

# ---------------------------------------------------------------------------
# 규칙 정의
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str


def _r(rule_id: str, pattern: str, severity: Severity, description: str) -> _Rule:
    return _Rule(
        rule_id=rule_id,
        pattern=re.compile(pattern, re.IGNORECASE | re.DOTALL),
        severity=severity,
        description=description,
    )


# ── SQL Injection ──────────────────────────────────────────────────────────

_SQL_RULES: tuple[_Rule, ...] = (
    # 인증 우회: ' OR 1=1 / ' OR 'a'='a
    _r("A05-SQL-001", r"'\s*(OR|AND)\s+[\w'\"]+\s*=\s*[\w'\"]+",
       Severity.CRITICAL, "SQL 인증 우회 (OR/AND 조건)"),

    # 구문 종료 후 DDL/DML 삽입
    _r("A05-SQL-002", r"';\s*(DROP|DELETE|INSERT|UPDATE|CREATE|ALTER|EXEC|EXECUTE)\b",
       Severity.CRITICAL, "SQL 구문 종료 후 DDL/DML 삽입"),

    # UNION 기반 추출
    _r("A05-SQL-003", r"\bUNION\b\s+(ALL\s+)?\bSELECT\b",
       Severity.CRITICAL, "UNION SELECT 기반 데이터 추출"),

    # SQL 주석 우회 (--, #, /**/)
    _r("A05-SQL-004", r"(--[ \t]|--$|#\s*$|/\*[\s\S]*?\*/)",
       Severity.HIGH, "SQL 주석을 이용한 우회"),

    # Time-based Blind SQLi
    _r("A05-SQL-005", r"\b(SLEEP|BENCHMARK|PG_SLEEP|WAITFOR\s+DELAY)\s*\(",
       Severity.CRITICAL, "Time-based Blind SQL Injection"),

    # Error-based Blind SQLi
    _r("A05-SQL-006", r"\b(EXTRACTVALUE|UPDATEXML|EXP|FLOOR\s*\(RAND)\s*\(",
       Severity.HIGH, "Error-based Blind SQL Injection"),

    # MSSQL 시스템 함수
    _r("A05-SQL-007", r"\b(XP_CMDSHELL|SP_EXECUTESQL|SP_MAKEWEBTASK|OPENROWSET)\b",
       Severity.CRITICAL, "MSSQL 시스템 함수 호출"),

    # Stacked Query
    _r("A05-SQL-008", r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\b",
       Severity.HIGH, "Stacked Query (세미콜론 이후 추가 쿼리)"),

    # 16진수 인코딩 우회 (0x41 등)
    _r("A05-SQL-009", r"0x[0-9a-fA-F]{4,}",
       Severity.MEDIUM, "SQL 16진수 인코딩 우회"),
)

# ── OS Command Injection ───────────────────────────────────────────────────

_CMD_RULES: tuple[_Rule, ...] = (
    # 명령어 체인 연산자 뒤 위험 명령
    _r("A05-CMD-001",
       r"[;&|`]\s*(cat|ls|id|whoami|uname|pwd|env|printenv|wget|curl|nc|bash|sh|python|perl|ruby)\b",
       Severity.CRITICAL, "명령어 체인을 통한 OS 명령 실행"),

    # 서브쉘 치환
    _r("A05-CMD-002", r"\$\([^)]{1,200}\)",
       Severity.CRITICAL, "서브쉘 치환 $() 를 통한 명령 실행"),

    # 백틱 실행
    _r("A05-CMD-003", r"`[^`]{1,200}`",
       Severity.CRITICAL, "백틱을 이용한 명령 실행"),

    # 경로 포함 실행 바이너리
    _r("A05-CMD-004", r"(/bin/|/usr/bin/|/etc/)(bash|sh|cat|rm|chmod|chown|wget|curl)",
       Severity.CRITICAL, "절대경로 실행 파일 참조"),

    # 파일 시스템 정찰
    _r("A05-CMD-005", r"/etc/(passwd|shadow|hosts|crontab|sudoers)",
       Severity.HIGH, "민감한 시스템 파일 접근 시도"),

    # 아웃밴드 데이터 유출
    _r("A05-CMD-006", r"(wget|curl)\s+.{0,100}(http|ftp)://",
       Severity.HIGH, "wget/curl 을 통한 외부 통신 시도"),
)

# ── Cross-Site Scripting (XSS) ─────────────────────────────────────────────

_XSS_RULES: tuple[_Rule, ...] = (
    # script 태그
    _r("A05-XSS-001", r"<script[\s>]",
       Severity.HIGH, "XSS: <script> 태그 삽입"),

    # javascript: URL 스킴
    _r("A05-XSS-002", r"javascript\s*:",
       Severity.HIGH, "XSS: javascript: URL 스킴"),

    # 이벤트 핸들러
    _r("A05-XSS-003", r"on(load|error|click|mouseover|focus|blur|submit|keyup|keydown|change|input)\s*=",
       Severity.HIGH, "XSS: 인라인 이벤트 핸들러"),

    # iframe 삽입
    _r("A05-XSS-004", r"<iframe[\s>]",
       Severity.HIGH, "XSS: <iframe> 태그 삽입"),

    # document.cookie 탈취 패턴
    _r("A05-XSS-005", r"document\.(cookie|location|write|writeln)",
       Severity.HIGH, "XSS: DOM 조작을 통한 쿠키 탈취 또는 리다이렉트"),

    # eval 실행
    _r("A05-XSS-006", r"\beval\s*\(",
       Severity.HIGH, "XSS: eval() 를 통한 코드 실행"),

    # SVG/img onerror
    _r("A05-XSS-007", r"<(img|svg|body|input)[^>]*onerror\s*=",
       Severity.HIGH, "XSS: onerror 이벤트를 통한 스크립트 실행"),

    # CSS expression (IE legacy)
    _r("A05-XSS-008", r"expression\s*\(",
       Severity.MEDIUM, "XSS: CSS expression() 실행"),

    # HTML 인코딩 우회 (&#x 패턴)
    _r("A05-XSS-009", r"&#[xX]?[0-9a-fA-F]{2,6};",
       Severity.MEDIUM, "XSS: HTML 문자 인코딩 우회"),
)

# ── LDAP Injection ─────────────────────────────────────────────────────────

_LDAP_RULES: tuple[_Rule, ...] = (
    _r("A05-LDAP-001", r"\)\s*\(\s*[|&]",
       Severity.HIGH, "LDAP 필터 조작 (OR/AND 연산자 삽입)"),

    _r("A05-LDAP-002", r"\*\)\s*\(",
       Severity.HIGH, "LDAP 와일드카드를 이용한 인증 우회"),

    _r("A05-LDAP-003", r"\(\s*(uid|cn|sn|mail|ou|dc|objectClass)\s*=\s*\*",
       Severity.HIGH, "LDAP 속성 와일드카드 검색"),
)

# ── XPath Injection ────────────────────────────────────────────────────────

_XPATH_RULES: tuple[_Rule, ...] = (
    _r("A05-XPATH-001", r"'\s*or\s*'[\w\d]+'\s*=\s*'[\w\d]+",
       Severity.HIGH, "XPath 인젝션: OR 조건"),

    _r("A05-XPATH-002", r"(//|\.\./|/\.\./)",
       Severity.MEDIUM, "XPath 노드 순회 시도"),

    _r("A05-XPATH-003", r"\bstring-length\s*\(|\bsubstring\s*\(|\bcount\s*\(",
       Severity.MEDIUM, "XPath Blind 인젝션 함수 사용"),
)

# ── Expression Language / Template Injection ───────────────────────────────

_EL_RULES: tuple[_Rule, ...] = (
    # Spring EL / OGNL
    _r("A05-EL-001", r"\$\{\s*[^}]{1,200}\}",
       Severity.HIGH, "Expression Language(EL) 인젝션: ${...}"),

    _r("A05-EL-002", r"#\{\s*[^}]{1,200}\}",
       Severity.HIGH, "Expression Language(EL) 인젝션: #{...}"),

    # OGNL
    _r("A05-EL-003", r"%\{[^}]{1,200}\}",
       Severity.HIGH, "OGNL 인젝션: %{...}"),

    # Server-Side Template Injection
    _r("A05-SSTI-001", r"\{\{[\s\S]{1,200}\}\}",
       Severity.HIGH, "SSTI: Jinja2/Twig/Handlebars 템플릿 인젝션"),

    _r("A05-SSTI-002", r"\{%[\s\S]{1,200}%\}",
       Severity.HIGH, "SSTI: Jinja2 블록 태그 인젝션"),
)

# ── CRLF Injection ─────────────────────────────────────────────────────────

_CRLF_RULES: tuple[_Rule, ...] = (
    _r("A05-CRLF-001", r"(%0d%0a|%0D%0A|\r\n|\n)",
       Severity.MEDIUM, "CRLF 인젝션: HTTP 헤더 분할 시도"),

    _r("A05-CRLF-002", r"(%0a|%0d)(Set-Cookie|Location|Content-Type)",
       Severity.HIGH, "CRLF 인젝션: HTTP 응답 헤더 조작"),
)

# 모든 규칙을 단일 튜플로 통합
_ALL_RULES: tuple[_Rule, ...] = (
    *_SQL_RULES,
    *_CMD_RULES,
    *_XSS_RULES,
    *_LDAP_RULES,
    *_XPATH_RULES,
    *_EL_RULES,
    *_CRLF_RULES,
)

# ---------------------------------------------------------------------------
# 디코딩 헬퍼 — 인코딩 우회 대응
# ---------------------------------------------------------------------------

def _decode_layers(value: str) -> list[str]:
    """원본, URL 디코드 1회, URL 디코드 2회(이중 인코딩) 를 모두 반환."""
    variants: list[str] = [value]
    try:
        d1 = urllib.parse.unquote(value)
        if d1 != value:
            variants.append(d1)
        d2 = urllib.parse.unquote(d1)
        if d2 != d1:
            variants.append(d2)
    except Exception:
        pass
    return variants


def _decode_plus(value: str) -> list[str]:
    """쿼리스트링에서 + → 공백 치환 포함."""
    variants = _decode_layers(value)
    plus = value.replace("+", " ")
    if plus not in variants:
        variants.extend(_decode_layers(plus))
    return variants

# ---------------------------------------------------------------------------
# 핵심 스캔 로직
# ---------------------------------------------------------------------------

def _scan_value(value: str, *, plus_decode: bool = False) -> list[Finding]:
    """단일 문자열 값에 대해 모든 규칙을 적용하고 Finding 목록을 반환."""
    findings: list[Finding] = []
    variants = _decode_plus(value) if plus_decode else _decode_layers(value)

    for rule in _ALL_RULES:
        for variant in variants:
            m = rule.pattern.search(variant)
            if m:
                matched_text = m.group(0)[:200]
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        evidence=f"{rule.description} | 탐지값: {matched_text!r}",
                        severity=rule.severity,
                    )
                )
                break  # 같은 규칙은 variant별로 중복 탐지 방지

    return findings


def _collect_targets(ctx: RequestContext) -> list[tuple[str, str]]:
    """(label, value) 쌍 목록 — 스캔 대상 전체 추출."""
    targets: list[tuple[str, str]] = []

    # URL 경로
    targets.append(("path", ctx.path))

    # 쿼리스트링 전체 + 파라미터별
    if ctx.query_string:
        targets.append(("query_raw", ctx.query_string))
        try:
            parsed = urllib.parse.parse_qs(ctx.query_string, keep_blank_values=True)
            for key, values in parsed.items():
                targets.append((f"query.{key}", key))
                for v in values:
                    targets.append((f"query.{key}", v))
        except Exception:
            pass

    # 요청 바디 미리보기
    if ctx.body_preview:
        targets.append(("body", ctx.body_preview))
        # JSON 바디라면 각 값도 개별 스캔
        try:
            import json
            obj = json.loads(ctx.body_preview)
            for k, v in _flatten_json(obj):
                targets.append((f"body.{k}", str(v)))
        except Exception:
            pass
        # URL-encoded 폼 바디
        try:
            if "application/x-www-form-urlencoded" in ctx.headers.get("content-type", ""):
                parsed_body = urllib.parse.parse_qs(ctx.body_preview, keep_blank_values=True)
                for key, values in parsed_body.items():
                    for v in values:
                        targets.append((f"form.{key}", v))
        except Exception:
            pass

    # 스캔 대상 헤더 값
    for header_name, header_value in ctx.headers.items():
        if header_name.lower() in _SCANNABLE_HEADERS:
            targets.append((f"header.{header_name}", header_value))

    return targets


def _flatten_json(obj: object, prefix: str = "") -> list[tuple[str, object]]:
    """JSON 객체를 재귀적으로 펼쳐 (경로, 값) 쌍을 반환."""
    items: list[tuple[str, object]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_key = f"{prefix}.{k}" if prefix else str(k)
            items.extend(_flatten_json(v, new_key))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            new_key = f"{prefix}[{i}]"
            items.extend(_flatten_json(v, new_key))
    else:
        items.append((prefix, obj))
    return items


def _deduplicate(findings: Sequence[Finding]) -> tuple[Finding, ...]:
    """동일 rule_id 는 첫 번째 Finding 만 유지."""
    seen: set[str] = set()
    result: list[Finding] = []
    for f in findings:
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            result.append(f)
    return tuple(result)

# ---------------------------------------------------------------------------
# 공개 인터페이스 — detector.py 가 호출하는 진입점
# ---------------------------------------------------------------------------

async def scan(ctx: RequestContext) -> ModuleScanResult:
    """A05:2025 Injection — 요청의 모든 입력값을 검사하여 인젝션 패턴을 탐지한다."""
    all_findings: list[Finding] = []

    for label, value in _collect_targets(ctx):
        plus = label.startswith("query") or label.startswith("form")
        findings = _scan_value(value, plus_decode=plus)
        all_findings.extend(findings)

    return ModuleScanResult(
        module_id=MODULE_ID,
        owasp_id=OWASP_ID,
        findings=_deduplicate(all_findings),
    )
