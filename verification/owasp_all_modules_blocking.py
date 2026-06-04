"""OWASP A01~A10 모듈이 모두 실제 차단 Finding을 만들 수 있는지 검증."""

from __future__ import annotations

import asyncio

import pytest

from detector import all_findings, scan_request, waf_blocking_findings
from owasp.types import RequestContext, Severity


def _ctx(
    *,
    path: str = "/",
    query: str = "",
    headers: dict[str, str] | None = None,
    body: str = "",
    method: str = "GET",
) -> RequestContext:
    return RequestContext(
        method=method,
        path=path,
        query_string=query,
        headers=headers or {},
        body_preview=body,
    )


@pytest.mark.parametrize(
    ("module_id", "ctx"),
    [
        ("a01", _ctx(path="/admin", query="role=admin")),
        ("a02", _ctx(path="/.env")),
        ("a03", _ctx(path="/package-lock.json")),
        ("a04", _ctx(query="url=http://169.254.169.254/latest/meta-data")),
        ("a05", _ctx(query="q=' OR 1=1--")),
        ("a06", _ctx(query="isAdmin=true")),
        ("a07", _ctx(path="/login", query="username=admin&password=admin")),
        (
            "a08",
            _ctx(
                headers={"content-type": "multipart/form-data"},
                body='Content-Disposition: form-data; name="file"; filename="shell.php"',
                method="POST",
            ),
        ),
        ("a09", _ctx(query="log=disabled")),
        ("a10", _ctx(path="/api/Products/undefined")),
    ],
)
def test_each_owasp_module_can_produce_blocking_finding(
    module_id: str,
    ctx: RequestContext,
) -> None:
    results = asyncio.run(scan_request(ctx))
    target = next(r for r in results if r.module_id == module_id)
    assert target.findings, f"{module_id} did not produce a finding"

    blocking = waf_blocking_findings(all_findings(results), Severity.HIGH)
    assert any(f.rule_id.lower().startswith(module_id) for f in blocking)
