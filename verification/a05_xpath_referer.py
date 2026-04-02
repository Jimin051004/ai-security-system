"""A05 XPath: Referer 의 정상 URL 에서 오탐 없음, 실제 패턴은 탐지."""

from __future__ import annotations

import asyncio

from owasp import a05
from owasp.types import RequestContext


def test_xpath002_no_false_positive_on_referer_http_url() -> None:
    """http://... 의 // 는 스킴 일부 — A05-XPATH-002 오탐 금지."""
    ctx = RequestContext(
        method="GET",
        path="/favicon.ico",
        query_string="",
        headers={"referer": "http://192.168.0.39:8080/"},
        body_preview="",
    )
    r = asyncio.run(a05.scan(ctx))
    assert not any(f.rule_id == "A05-XPATH-002" for f in r.findings)


def test_xpath002_detects_axis_after_non_alnum() -> None:
    """XPath 축 // 가 스킴이 아닌 위치에 있으면 탐지."""
    ctx = RequestContext(
        method="POST",
        path="/api/x",
        query_string="",
        headers={"content-type": "application/json"},
        body_preview=r'{"payload":"(//user[@id=1])"}',
    )
    r = asyncio.run(a05.scan(ctx))
    assert any(f.rule_id == "A05-XPATH-002" for f in r.findings)


def test_xpath002_detects_double_slash_in_query_value() -> None:
    """쿼리 값이 XPath 축으로 // 로 시작하면 탐지(http:// 가 아님)."""
    ctx = RequestContext(
        method="GET",
        path="/search",
        query_string="q=//users",
        headers={},
        body_preview="",
    )
    r = asyncio.run(a05.scan(ctx))
    assert any(f.rule_id == "A05-XPATH-002" for f in r.findings)
