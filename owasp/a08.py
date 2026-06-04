"""A08:2025 — Software or Data Integrity Failures
파일 업로드 공격 + 역직렬화 취약점 + 무결성 우회 패턴 탐지.

탐지 유형:
  1. 위험한 파일 확장자 업로드 (PHP, JSP, ASP, 웹쉘 등)
  2. Content-Type 위조 (image/jpeg 로 위장한 PHP 업로드)
  3. 파일명 경로 탈출 (../../../etc/passwd)
  4. 역직렬화 공격 패턴 (Java, PHP unserialize, pickle)
  5. XXE (XML External Entity) 인젝션
  6. ZIP 슬립 (zip bomb, 경로 탈출)
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Sequence

from owasp.types import Finding, ModuleScanResult, RequestContext, Severity

OWASP_ID = "A08:2025"
MODULE_ID = "a08"
TITLE = "Software or Data Integrity Failures"


@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str


def _r(rule_id: str, pattern: str, severity: Severity, description: str) -> _Rule:
    return _Rule(rule_id, re.compile(pattern, re.IGNORECASE | re.DOTALL), severity, description)


_RULES: tuple[_Rule, ...] = (
    # ── 위험한 파일 확장자 ─────────────────────────────────────────────────
    _r("A08-UPLOAD-001",
       r"filename\s*=\s*['\"]?[^'\";\n]*\.(php[3-7]?|phtml|php-s|phar)\b",
       Severity.CRITICAL, "PHP 웹쉘 파일 업로드 시도"),

    _r("A08-UPLOAD-002",
       r"filename\s*=\s*['\"]?[^'\";\n]*\.(asp|aspx|asmx|ashx|cshtml|vbhtml)\b",
       Severity.CRITICAL, "ASP/ASPX 웹쉘 파일 업로드 시도"),

    _r("A08-UPLOAD-003",
       r"filename\s*=\s*['\"]?[^'\";\n]*\.(jsp|jspx|jw|jsw|jsf|war)\b",
       Severity.CRITICAL, "JSP/WAR 웹쉘 파일 업로드 시도"),

    _r("A08-UPLOAD-004",
       r"filename\s*=\s*['\"]?[^'\";\n]*\.(cgi|pl|py|rb|sh|bash|ksh|exe|dll|so|bat|cmd|ps1)\b",
       Severity.HIGH, "실행 파일/스크립트 업로드 시도"),

    _r("A08-UPLOAD-005",
       r"filename\s*=\s*['\"]?[^'\";\n]*\.(shtml|shtm|stm|hta|htaccess|htpasswd)\b",
       Severity.HIGH, "서버 설정/포함 파일 업로드 시도"),

    # ── Content-Type 위조 ─────────────────────────────────────────────────
    _r("A08-MIME-001",
       r"Content-Type:\s*(?:image|text|application)/(?:jpeg|png|gif|plain)\s*.*?\bfilename\s*=\s*[^;\"'\n]*\.(php|asp|jsp|cgi|sh|exe)\b",
       Severity.HIGH, "Content-Type 위조를 통한 웹쉘 업로드"),

    # ── 파일명 경로 탈출 ──────────────────────────────────────────────────
    _r("A08-PATH-001",
       r"filename\s*=\s*['\"]?(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/){1,}",
       Severity.CRITICAL, "파일명 경로 탈출 (Directory Traversal via filename)"),

    _r("A08-PATH-002",
       r"filename\s*=\s*['\"]?[^'\";\n]*%00",
       Severity.HIGH, "파일명 null byte 삽입 (확장자 우회)"),

    # ── 역직렬화 공격 ─────────────────────────────────────────────────────
    _r("A08-DESER-001",
       r"(?:O:\d+:\"[A-Za-z_]\w*\"|\bserialize\s*\(|rO0ABX|ACED0005)",
       Severity.CRITICAL, "PHP/Java 역직렬화 페이로드 탐지"),

    _r("A08-DESER-002",
       r"(?:__reduce__|__reduce_ex__|pickle\.loads|cPickle\.loads)",
       Severity.HIGH, "Python Pickle 역직렬화 공격 패턴"),

    _r("A08-DESER-003",
       r"(?:ObjectInputStream|readObject\s*\(\s*\)|Runtime\.exec|ProcessBuilder)",
       Severity.HIGH, "Java 역직렬화 위험 클래스 참조"),

    # ── XXE (XML External Entity) ─────────────────────────────────────────
    _r("A08-XXE-001",
       r"<!ENTITY\s+\w+\s+(?:SYSTEM|PUBLIC)\s+['\"]",
       Severity.CRITICAL, "XXE: XML External Entity 선언"),

    _r("A08-XXE-002",
       r"<!DOCTYPE[^>]*\[[\s\S]{0,500}<!ENTITY",
       Severity.CRITICAL, "XXE: DOCTYPE 내 ENTITY 삽입"),

    _r("A08-XXE-003",
       r"&(?:xxe|test|exploit|blind|oob);\s*",
       Severity.HIGH, "XXE: 외부 엔티티 참조 패턴"),

    # ── ZIP Slip / 압축파일 경로 탈출 ─────────────────────────────────────
    _r("A08-ZIP-001",
       r"(?:\.zip|\.tar|\.gz|\.tgz|\.jar|\.war).*?(?:\.\./|%2e%2e%2f)",
       Severity.HIGH, "ZIP Slip: 압축 파일 내 경로 탈출"),

    # ── 대용량 파일 탐지 (Content-Length 검사) ────────────────────────────
    # 주: Content-Length 헤더 기반 — 매우 큰 업로드 탐지
    _r("A08-SIZE-001",
       r"^(?:[5-9]\d{8}|[1-9]\d{9,})\s*$",
       Severity.MEDIUM, "비정상적으로 큰 Content-Length (500MB+)"),
)


def _decode_layers(value: str) -> list[str]:
    variants: list[str] = [value]
    try:
        d1 = urllib.parse.unquote(value)
        if d1 != value:
            variants.append(d1)
    except Exception:
        pass
    return variants


def _collect_targets(ctx: RequestContext) -> list[tuple[str, str]]:
    targets: list[tuple[str, str]] = []

    # Content-Type 헤더 (multipart 업로드 탐지)
    ct = ctx.headers.get("content-type", "")
    if ct:
        targets.append(("header.content-type", ct))

    # Content-Length 헤더
    cl = ctx.headers.get("content-length", "")
    if cl:
        targets.append(("header.content-length", cl.strip()))

    # 바디 미리보기 (multipart form-data, XML 등)
    if ctx.body_preview:
        targets.append(("body", ctx.body_preview))

    # 경로 (파일명 포함 경로)
    if ctx.path:
        targets.append(("path", ctx.path))

    return targets


def _scan_value(value: str, *, location: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    variants = _decode_layers(value)
    for rule in _RULES:
        for variant in variants:
            m = rule.pattern.search(variant)
            if m:
                matched = m.group(0)[:200]
                findings.append(Finding(
                    rule_id=rule.rule_id,
                    evidence=f"{rule.description} | 탐지값: {matched!r}",
                    severity=rule.severity,
                    location=location,
                ))
                break
    return findings


def _deduplicate(findings: Sequence[Finding]) -> tuple[Finding, ...]:
    seen: set[str] = set()
    result: list[Finding] = []
    for f in findings:
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            result.append(f)
    return tuple(result)


async def scan(ctx: RequestContext) -> ModuleScanResult:
    """A08:2025 파일 업로드/역직렬화/XXE 공격 탐지."""
    all_findings: list[Finding] = []
    for label, value in _collect_targets(ctx):
        all_findings.extend(_scan_value(value, location=label))
    return ModuleScanResult(
        module_id=MODULE_ID,
        owasp_id=OWASP_ID,
        findings=_deduplicate(all_findings),
    )
