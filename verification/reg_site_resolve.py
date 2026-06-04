"""registration_resolve_site_id — URL 또는 직접 입력 site_id 처리."""

from __future__ import annotations

import pytest

import auth


@pytest.mark.parametrize(
    ("inp", "expected"),
    [
        ("juiceshop", "juiceshop"),
        ("Juice_shop", "juice-shop"),
        ("http://192.168.100.151:3000/#/", "192-168-100-151-p-3000"),
        ("HTTP://192.168.100.151:3000", "192-168-100-151-p-3000"),
        ("192.168.100.151:3000", "192-168-100-151-p-3000"),
        ("192.168.100.151:3000/foo", "192-168-100-151-p-3000"),
        ("https://labs.example.net:8443/path", "labs-example-net-p-8443"),
        ("labs.example.net", "labs-example-net"),
        ("labs.example.net:8443", "labs-example-net-p-8443"),
    ],
)
def test_registration_resolve_site_id_ok(inp: str, expected: str) -> None:
    sid, err = auth.registration_resolve_site_id(inp)
    assert err is None
    assert sid == expected


@pytest.mark.parametrize(
    "inp",
    [
        "",
        "::1",
        "[::1]:3000",
        "admin",
        "http:///",
    ],
)
def test_registration_resolve_site_id_rejected(inp: str) -> None:
    sid, err = auth.registration_resolve_site_id(inp)
    assert sid is None
    assert err
