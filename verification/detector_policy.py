"""WAF 정책·집계 로직 (main / 실제 업스트림 불필요)."""

from __future__ import annotations

from detector import (
    all_findings,
    findings_at_or_above_severity,
    parse_severity,
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


def test_all_findings_flattens_modules() -> None:
    f = Finding("x", "e", Severity.MEDIUM)
    results = [
        ModuleScanResult("a01", "A01:2025", ()),
        ModuleScanResult("a05", "A05:2025", (f,)),
    ]
    assert all_findings(results) == [f]
