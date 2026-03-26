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

    # 로그인 필드 등: 닫는 따옴표 뒤 `-` / `--` / `#` / `/*` (Juice Shop 이메일 인젝션 시연)
    _r(
        "A05-SQL-010",
        r"'\s*-{1,}\s*$|'\s*-{2,}|'\s+#\s*$|'\s+/\*",
        Severity.HIGH,
        "SQL: 따옴표 탈출 후 주석·구문 패턴 (로그인 인젝션 시도)",
    ),
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

def _scan_value(
    value: str,
    *,
    plus_decode: bool = False,
    location: str | None = None,
) -> list[Finding]:
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
                        location=location,
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
# 차단 HTML 페이지 — 인젝션 유형별 한국어 메시지 + 탐지 근거 표시
# ---------------------------------------------------------------------------

_RULE_TYPE_MAP: dict[str, str] = {
    "A05-SQL":   "SQL Injection",
    "A05-CMD":   "OS Command Injection",
    "A05-XSS":   "XSS (크로스 사이트 스크립팅)",
    "A05-LDAP":  "LDAP Injection",
    "A05-XPATH": "XPath Injection",
    "A05-SSTI":  "SSTI / EL Injection",
    "A05-CRLF":  "CRLF Injection",
}

_SEV_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.NONE: 1,
}

_TITLE_MAP: dict[str, str] = {
    "SQL Injection":               "SQL Injection 공격이 차단되었습니다",
    "OS Command Injection":        "OS Command Injection 공격이 차단되었습니다",
    "XSS (크로스 사이트 스크립팅)": "XSS 공격이 차단되었습니다",
    "LDAP Injection":              "LDAP Injection 공격이 차단되었습니다",
    "XPath Injection":             "XPath Injection 공격이 차단되었습니다",
    "SSTI / EL Injection":         "SSTI 공격이 차단되었습니다",
    "CRLF Injection":              "CRLF Injection 공격이 차단되었습니다",
}

_SEV_CSS: dict[Severity, tuple[str, str]] = {
    Severity.CRITICAL: ("CRITICAL", "sev-critical"),
    Severity.HIGH:     ("HIGH",     "sev-high"),
    Severity.MEDIUM:   ("MEDIUM",   "sev-medium"),
    Severity.LOW:      ("LOW",      "sev-low"),
    Severity.NONE:     ("NONE",     "sev-low"),
}

_BLOCK_PAGE_CSS = """
  *{box-sizing:border-box;margin:0;padding:0}
  body{
    min-height:100vh;display:flex;align-items:center;justify-content:center;
    padding:2rem;font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
    color:#f0f4fc;
    background:#060912;
    background:
      radial-gradient(ellipse 110% 85% at 5% -15%,rgba(59,130,246,.28),transparent 52%),
      radial-gradient(ellipse 90% 70% at 95% 5%,rgba(248,113,113,.22),transparent 48%),
      linear-gradient(168deg,#0d1326 0%,#080c18 38%,#060912 100%);
  }
  .card{
    background:linear-gradient(155deg,rgba(30,38,62,.88),rgba(14,18,32,.96));
    border:1px solid rgba(248,113,113,.35);border-radius:16px;
    padding:2rem 2.5rem;max-width:620px;width:100%;
    box-shadow:0 8px 40px rgba(248,113,113,.1),0 4px 24px rgba(0,0,0,.45);
  }
  .icon{font-size:2.75rem;margin-bottom:.6rem}
  h1{font-size:1.45rem;font-weight:800;color:#fca5a5;
     margin-bottom:.3rem;letter-spacing:-.03em}
  .subtitle{font-size:.875rem;color:#8b9cc4;margin-bottom:1.25rem;line-height:1.5}
  .type-badge{
    display:inline-flex;align-items:center;gap:.4rem;
    padding:.38rem .9rem;
    background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.3);
    border-radius:999px;font-size:.82rem;font-weight:700;color:#fca5a5;
    margin-bottom:1.25rem;
  }
  .findings{
    background:rgba(0,0,0,.22);border:1px solid rgba(129,140,248,.15);
    border-radius:10px;overflow:hidden;margin-bottom:1.5rem;
  }
  .finding-row{
    display:flex;align-items:flex-start;gap:.75rem;
    padding:.6rem .9rem;border-top:1px solid rgba(255,255,255,.04);
    font-size:.78rem;
  }
  .finding-row:first-child{border-top:none}
  .sev{
    flex-shrink:0;padding:.18rem .52rem;border-radius:999px;
    font-size:.66rem;font-weight:700;letter-spacing:.04em;
  }
  .sev-critical{background:rgba(239,68,68,.18);color:#fca5a5;border:1px solid rgba(239,68,68,.32)}
  .sev-high{background:rgba(251,146,60,.15);color:#fdba74;border:1px solid rgba(251,146,60,.28)}
  .sev-medium{background:rgba(250,204,21,.12);color:#fde047;border:1px solid rgba(250,204,21,.22)}
  .sev-low{background:rgba(52,211,153,.1);color:#34d399;border:1px solid rgba(52,211,153,.2)}
  .rule-id{color:#a5b4fc;font-family:ui-monospace,"SF Mono",Consolas,monospace;
           font-size:.71rem;margin-bottom:.15rem}
  .evidence{color:#8b9cc4;word-break:break-all;line-height:1.4}
  .footer{font-size:.73rem;color:#8b9cc4;line-height:1.6}
  .back-btn{
    display:inline-flex;align-items:center;gap:.45rem;margin-top:1.1rem;
    padding:.55rem 1.2rem;
    background:linear-gradient(135deg,#3b82f6,#6366f1 50%,#a855f7);
    border:none;border-radius:10px;color:#fff;font-size:.85rem;font-weight:600;
    font-family:inherit;cursor:pointer;text-decoration:none;
    box-shadow:0 4px 20px rgba(99,102,241,.3);
    transition:filter .15s,transform .15s;
  }
  .back-btn:hover{filter:brightness(1.1);transform:translateY(-1px)}
"""


def _html_esc(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )


def _infer_injection_type(findings: tuple[Finding, ...]) -> str:
    sorted_f = sorted(findings, key=lambda f: _SEV_RANK.get(f.severity, 0), reverse=True)
    for f in sorted_f:
        for prefix, name in _RULE_TYPE_MAP.items():
            if f.rule_id.startswith(prefix):
                return name
    return "Injection"


def make_block_html(findings: tuple[Finding, ...]) -> str:
    """인젝션 탐지 시 브라우저에 반환할 403 차단 HTML 페이지를 생성한다."""
    injection_type = _infer_injection_type(findings)
    title = _TITLE_MAP.get(injection_type, "Injection 공격이 차단되었습니다")

    sorted_findings = sorted(
        findings, key=lambda f: _SEV_RANK.get(f.severity, 0), reverse=True
    )
    rows: list[str] = []
    for f in sorted_findings:
        label, css = _SEV_CSS.get(f.severity, ("?", "sev-low"))
        ev = f.evidence[:130] + "…" if len(f.evidence) > 130 else f.evidence
        rows.append(
            f'<div class="finding-row">'
            f'<span class="sev {css}">{label}</span>'
            f'<div>'
            f'<div class="rule-id">{_html_esc(f.rule_id)}</div>'
            f'<div class="evidence">{_html_esc(ev)}</div>'
            f'</div>'
            f'</div>'
        )
    findings_html = "\n".join(rows)

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WAF — 요청 차단됨</title>
  <style>{_BLOCK_PAGE_CSS}</style>
</head>
<body>
  <div class="card">
    <div class="icon">🚫</div>
    <h1>{_html_esc(title)}</h1>
    <p class="subtitle">
      WAF(Web Application Firewall)가 악성 인젝션 패턴을 탐지하여<br>
      이 요청을 업스트림 서버로 전달하지 않고 차단했습니다.
    </p>
    <div class="type-badge">🔍 {_html_esc(injection_type)} 탐지됨</div>
    <div class="findings">
{findings_html}
    </div>
    <p class="footer">
      OWASP A05:2025 — Injection 정책에 의해 차단되었습니다.<br>
      정상적인 요청이라면 관리자에게 문의하세요.
    </p>
    <a class="back-btn" href="javascript:history.back()">← 이전 페이지로</a>
  </div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# 공개 인터페이스 — detector.py 가 호출하는 진입점
# ---------------------------------------------------------------------------

async def scan(ctx: RequestContext) -> ModuleScanResult:
    """A05:2025 Injection — 요청의 모든 입력값을 검사하여 인젝션 패턴을 탐지한다."""
    all_findings: list[Finding] = []

    for label, value in _collect_targets(ctx):
        plus = label.startswith("query") or label.startswith("form")
        findings = _scan_value(value, plus_decode=plus, location=label)
        all_findings.extend(findings)

    return ModuleScanResult(
        module_id=MODULE_ID,
        owasp_id=OWASP_ID,
        findings=_deduplicate(all_findings),
    )
