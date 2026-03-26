"""A05: 로그인·폼 본문의 SQLi 패턴 (Juice Shop 이메일 필드 등)."""

from __future__ import annotations

import asyncio

from owasp import a05
from owasp.types import RequestContext


def test_a05_detects_juice_shop_style_email_quote_dash() -> None:
    """스크린샷 유형: admin@juice-sh.op' -"""
    body = '{"email":"admin@juice-sh.op\' -","password":"x"}'
    ctx = RequestContext(
        method="POST",
        path="/rest/user/login",
        query_string="",
        headers={"content-type": "application/json"},
        body_preview=body,
    )
    r = asyncio.run(a05.scan(ctx))
    ids = {f.rule_id for f in r.findings}
    assert "A05-SQL-010" in ids


def test_a05_detects_quote_double_dash_comment() -> None:
    ctx = RequestContext(
        method="POST",
        path="/rest/user/login",
        query_string="",
        headers={"content-type": "application/json"},
        body_preview='{"email":"a@b.c\'--"}',
    )
    r = asyncio.run(a05.scan(ctx))
    assert any(f.rule_id == "A05-SQL-010" for f in r.findings)
