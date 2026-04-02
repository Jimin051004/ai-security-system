"""WAF 정책·집계 로직 (main / 실제 업스트림 불필요)."""

from __future__ import annotations

from detector import (
    all_findings,
    findings_at_or_above_severity,
    parse_severity,
    waf_blocking_findings,
)
from owasp.types import Finding, ModuleScanResult, Severity


def test_parse_severity_default_and_valid() -> None:
    assert parse_severity("", Severity.HIGH) == Severity.HIGH
    assert parse_severity("medium", Severity.HIGH) == Severity.MEDIUM
    assert parse_severity("CRITICAL".lower(), Severity.HIGH) == Severity.CRITICAL


def test_parse_severity_invalid_falls_back() -> None:
    assert parse_severity("not-a-severity", Severity.HIGH) == Severity.HIGH


def test_findings_at_or_above_severity() -> None:
    f_low = Finding("r1", "x", Severity.LOW)
    f_high = Finding("r2", "y", Severity.HIGH)
    f_crit = Finding("r3", "z", Severity.CRITICAL)
    all_f = [f_low, f_high, f_crit]
    assert findings_at_or_above_severity(all_f, Severity.HIGH) == [f_high, f_crit]
    assert findings_at_or_above_severity(all_f, Severity.CRITICAL) == [f_crit]
    assert findings_at_or_above_severity(all_f, Severity.LOW) == all_f


def test_waf_blocking_findings_includes_a05_below_threshold() -> None:
    """A05 인젝션 규칙은 WAF_BLOCK_MIN_SEVERITY 미만이어도 차단 후보에 넣는다."""
    f_a05_med = Finding("A05-SQL-009", "hex", Severity.MEDIUM, "query.q")
    f_other_low = Finding("A10-FOO-001", "x", Severity.LOW)
    findings = [f_a05_med, f_other_low]
    assert findings_at_or_above_severity(findings, Severity.HIGH) == []
    assert waf_blocking_findings(findings, Severity.HIGH) == [f_a05_med]


def test_all_findings_flattens_modules() -> None:
    f = Finding("x", "e", Severity.MEDIUM)
    results = [
        ModuleScanResult("a01", "A01:2025", ()),
        ModuleScanResult("a05", "A05:2025", (f,)),
    ]
    assert all_findings(results) == [f]
