"""정상 Juice Shop 트래픽이 WAF 룰에 오탐 차단되지 않는지 검증."""

from __future__ import annotations

import asyncio

import owasp.a01 as a01
import owasp.a04 as a04
from main import _is_upstream_static_asset
from owasp.types import RequestContext


def _ctx(
    *,
    path: str = "/",
    query: str = "",
    headers: dict[str, str] | None = None,
    body: str = "",
) -> RequestContext:
    return RequestContext(
        method="GET",
        path=path,
        query_string=query,
        headers=headers or {},
        body_preview=body,
    )


def test_static_assets_bypass_waf_scan() -> None:
    """SPA 렌더링 필수 파일은 공격 입력 지점이 아니라 빌드 산출물이므로 통과시킨다."""
    assert _is_upstream_static_asset("styles.css", "GET") is True
    assert _is_upstream_static_asset("main.js", "GET") is True
    assert _is_upstream_static_asset("chunk-24EZLZ4I.js", "GET") is True
    assert _is_upstream_static_asset("assets/public/favicon_js.ico", "GET") is True
    assert _is_upstream_static_asset("rest/products/search", "GET") is False
    assert _is_upstream_static_asset("upload", "POST") is False


def test_juice_shop_bootstrap_config_not_a01_false_positive() -> None:
    """Juice Shop 정상 초기화 API는 `/admin` 문자열을 포함하지만 관리자 페이지 직접 접근이 아니다."""
    result = asyncio.run(a01.scan(_ctx(path="/rest/admin/application-configuration")))
    assert result.findings == ()


def test_a01_admin_direct_access_still_detected() -> None:
    result = asyncio.run(a01.scan(_ctx(path="/admin")))
    assert any(f.rule_id == "A01-BAC-001" for f in result.findings)


def test_private_ip_referer_not_ssrf_false_positive() -> None:
    """브라우저의 같은 출처 Referer가 사설 IP여도 SSRF 입력값으로 보지 않는다."""
    result = asyncio.run(
        a04.scan(
            _ctx(
                headers={
                    "referer": "http://192.168.100.155:8081/",
                    "origin": "http://192.168.100.155:8081",
                }
            )
        )
    )
    assert result.findings == ()


def test_ssrf_query_payload_still_detected() -> None:
    result = asyncio.run(
        a04.scan(_ctx(query="url=http://169.254.169.254/latest/meta-data"))
    )
    assert any(f.rule_id == "A04-SSRF-001" for f in result.findings)
