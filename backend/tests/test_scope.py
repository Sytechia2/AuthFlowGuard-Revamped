"""Tests for the browser scope boundary and URL redaction."""

import pytest
from authflowguard.models import TargetScope
from authflowguard.scope import (
    url_is_in_scope,
    url_without_query_keeping_route,
    url_without_query_or_fragment,
)


def test_url_is_in_scope_when_origin_is_permitted() -> None:
    target = TargetScope(
        target_url="https://app.example/login",
        permitted_origins=["https://app.example", "https://api.example"],
    )

    assert url_is_in_scope("https://api.example/session", target)
    assert not url_is_in_scope("https://unapproved.example/session", target)
    assert not url_is_in_scope("https://api.example.attacker.test/session", target)
    assert not url_is_in_scope("https://api.example@attacker.test/session", target)
    assert not url_is_in_scope("https://api.example:444/session", target)


@pytest.mark.parametrize(
    ("permitted_origin", "requested_url"),
    [
        ("https://APP.EXAMPLE", "https://app.example/account"),
        ("https://app.example:443", "https://app.example/account"),
        ("http://app.example:80", "http://app.example/account"),
        ("http://app.example:8080", "http://app.example:8080/account"),
    ],
)
def test_scope_normalizes_hostnames_and_default_ports(
    permitted_origin: str,
    requested_url: str,
) -> None:
    target = TargetScope(
        target_url=requested_url,
        permitted_origins=[permitted_origin],
    )

    assert url_is_in_scope(requested_url, target)


def test_url_redaction_removes_query_and_fragment() -> None:
    redacted_url = url_without_query_or_fragment(
        "https://app.example/callback?token=secret#account"
    )

    assert redacted_url == "https://app.example/callback"
    assert "secret" not in redacted_url


def test_url_redaction_removes_embedded_credentials_but_keeps_port() -> None:
    redacted_url = url_without_query_or_fragment(
        "https://username:password@app.example:8443/account?token=secret"
    )

    assert redacted_url == "https://app.example:8443/account"
    assert "username" not in redacted_url
    assert "password" not in redacted_url


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://127.0.0.1:3000/#/login", "http://127.0.0.1:3000/#/login"),
        (
            "https://app.example/?next=secret#/forgot-password",
            "https://app.example/#/forgot-password",
        ),
        ("https://app.example/#/2fa/enter", "https://app.example/#/2fa/enter"),
    ],
)
def test_route_redaction_keeps_hash_routes(url: str, expected: str) -> None:
    assert url_without_query_keeping_route(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://app.example/callback#access_token=secret",
        "https://app.example/#/reset?token=secret",
        "https://app.example/#/reset/8f14e45fceea167a5a36dedd4bea2543",
        "https://app.example/#/verify/c2VjcmV0LXRva2Vu",
        "https://app.example/#/verify/YWJjZGVmZ2hpams",
        "https://app.example/#account",
        "https://app.example/#/",
    ],
)
def test_route_redaction_strips_fragments_that_are_not_plain_routes(url: str) -> None:
    redacted_url = url_without_query_keeping_route(url)

    assert "#" not in redacted_url
    assert "secret" not in redacted_url
