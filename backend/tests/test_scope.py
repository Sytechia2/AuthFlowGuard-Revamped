"""Tests for the browser scope boundary and URL redaction."""

from authflowguard.models import TargetScope
from authflowguard.scope import url_is_in_scope, url_without_query_or_fragment


def test_url_is_in_scope_when_origin_is_permitted() -> None:
    target = TargetScope(
        target_url="https://app.example/login",
        permitted_origins=["https://app.example", "https://api.example"],
    )

    assert url_is_in_scope("https://api.example/session", target)
    assert not url_is_in_scope("https://unapproved.example/session", target)


def test_url_redaction_removes_query_and_fragment() -> None:
    redacted_url = url_without_query_or_fragment(
        "https://app.example/callback?token=secret#account"
    )

    assert redacted_url == "https://app.example/callback"
    assert "secret" not in redacted_url
