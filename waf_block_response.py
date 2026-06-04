"""WAF 차단 payload와 차단 페이지 응답 생성.

main.py는 요청 흐름을 담당하고, 이 모듈은 Finding을 UI/API에 표시 가능한
구조로 변환하는 책임만 가진다.
"""

from __future__ import annotations

import re
from typing import Any

import jinja2
from fastapi import Request
from fastapi.responses import HTMLResponse

from owasp import MODULES
from owasp.types import Finding, ModuleScanResult, Severity
from waf_rule_explain import rule_explain


def module_for_rule(
    results: list[ModuleScanResult],
    rule_id: str,
) -> ModuleScanResult | None:
    for r in results:
        if any(x.rule_id == rule_id for x in r.findings):
            return r
    return None


def module_title(module_id: str) -> str:
    if module_id == "ai":
        return "AI Second Pass"
    for m in MODULES:
        if m.module_id == module_id:
            return m.title
    return "—"


def attack_type_label(rule_id: str) -> str:
    u = rule_id.upper()
    if u.startswith("AI-"):
        return "AI Second Pass"
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
    if u.startswith("A05-"):
        return "Injection (기타)"
    if u.startswith("A06-"):
        return "Insecure Design (안전하지 않은 설계)"
    if u.startswith("A10-"):
        return "Exceptional Conditions (예외·비정상 처리)"
    return "기타 / 규칙 기반 탐지"


def finding_enriched_dict(
    results: list[ModuleScanResult],
    finding: Finding,
    *,
    evidence_max: int = 500,
) -> dict[str, str]:
    mod = module_for_rule(results, finding.rule_id)
    owasp_id = mod.owasp_id if mod else "—"
    category = module_title(mod.module_id) if mod else "—"
    ev_raw = finding.evidence or ""
    explain = rule_explain(finding.rule_id, ev_raw)
    ev = ev_raw
    if len(ev) > evidence_max:
        ev = ev[: evidence_max - 1] + "…"
    attack_type = attack_type_label(finding.rule_id)
    if finding.rule_id.upper().startswith("AI-"):
        m = re.search(r"attack_type=([^;]+)", ev_raw)
        if m:
            attack_type = m.group(1).strip()[:120] or attack_type
    return {
        "owasp_id": owasp_id,
        "category": category,
        "attack_type": attack_type,
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "location": finding.location or "—",
        "evidence": ev,
        "rule_explain": explain,
    }


def blocking_payload_dict(
    results: list[ModuleScanResult],
    blocking: list[Finding],
    min_severity: Severity,
    *,
    upstream_base: str,
) -> dict[str, Any]:
    return {
        "blocked": True,
        "policy": "min_severity",
        "min_severity": min_severity.value,
        "upstream": upstream_base,
        "findings": [finding_enriched_dict(results, f) for f in blocking],
    }


def prefer_waf_block_html(request: Request) -> bool:
    """브라우저 문서 탐색은 HTML 차단 페이지, API/XHR은 JSON 유지."""
    fmt = (request.query_params.get("__waf_block_format") or "").lower()
    if fmt == "json":
        return False
    if fmt == "html":
        return True
    if (request.headers.get("x-requested-with") or "").lower() == "xmlhttprequest":
        return False
    dest = (request.headers.get("sec-fetch-dest") or "").lower()
    if dest == "document":
        return True
    accept = (request.headers.get("accept") or "*/*").lower()
    parts = [p.strip().split(";")[0].strip() for p in accept.split(",") if p.strip()]
    if parts and parts[0] == "application/json":
        return False
    return True


def blocked_page_headlines(rows: list[dict[str, str]]) -> tuple[str, str]:
    if not rows:
        return "요청이 차단되었습니다", "WAF 정책에 의해 차단되었습니다."
    if len(rows) == 1:
        f0 = rows[0]
        atk = f0.get("attack_type") or "알 수 없는 공격 유형"
        h = f"{atk} 취약점이 발견되어 차단되었습니다"
        sub = (
            f"OWASP {f0.get('owasp_id', '—')} · {f0.get('category', '—')} · "
            f"규칙 {f0.get('rule_id', '—')} · 탐지 위치 {f0.get('location', '—')}"
        )
        return h, sub
    types: list[str] = []
    seen: set[str] = set()
    for r in rows:
        t = r.get("attack_type") or "—"
        if t not in seen:
            seen.add(t)
            types.append(t)
    types_str = ", ".join(types[:4])
    if len(types) > 4:
        types_str += f" 외 {len(types) - 4}종"
    h2 = "복수 취약점 패턴이 발견되어 차단되었습니다"
    sub2 = f"탐지된 유형: {types_str} (총 {len(rows)}건 규칙 매칭)"
    return h2, sub2


def waf_blocked_html_response(
    payload: dict[str, Any],
    *,
    jinja_env: jinja2.Environment,
) -> HTMLResponse:
    rows: list[dict[str, str]] = list(payload.get("findings") or [])
    if not rows:
        alert_message = "[WAF 차단] 위협이 탐지되어 요청이 차단되었습니다."
    elif len(rows) == 1:
        f0 = rows[0]
        alert_message = (
            f"[WAF 차단] {f0.get('owasp_id', '—')} · {f0.get('category', '—')}\n"
            f"{f0.get('attack_type', '—')}이(가) 확인되어 차단되었습니다.\n"
            f"규칙: {f0.get('rule_id', '—')} · 위치: {f0.get('location', '—')}"
        )
    else:
        f0 = rows[0]
        alert_message = (
            f"[WAF 차단] {len(rows)}건의 취약점 패턴이 탐지되어 차단되었습니다.\n"
            f"대표: {f0.get('owasp_id', '—')} — {f0.get('attack_type', '—')} "
            f"외 {len(rows) - 1}건"
        )
    headline, subline = blocked_page_headlines(rows)
    tpl = jinja_env.get_template("waf_blocked.html")
    html = tpl.render(
        rows=rows,
        headline=headline,
        subline=subline,
        boot={"alert_message": alert_message, "findings": rows},
    )
    return HTMLResponse(
        content=html,
        status_code=403,
        headers={"Cache-Control": "no-store"},
    )
