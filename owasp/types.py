from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Minimal request view passed into OWASP modules (expand when proxy exists)."""

    method: str
    path: str
    query_string: str
    headers: dict[str, str]
    body_preview: str


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    evidence: str
    severity: Severity
    # path, query.q, body 등 탐지된 입력 위치
    location: str | None = None


@dataclass(frozen=True, slots=True)
class ModuleScanResult:
    module_id: str
    owasp_id: str
    findings: tuple[Finding, ...]


def clean_result(*, module_id: str, owasp_id: str) -> ModuleScanResult:
    return ModuleScanResult(module_id=module_id, owasp_id=owasp_id, findings=())
