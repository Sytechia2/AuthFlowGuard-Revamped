"""Helpers that keep browser activity inside the developer-approved scope."""

import re
from urllib.parse import SplitResult, urlsplit, urlunsplit

from authflowguard.models import TargetScope


def url_without_query_or_fragment(url: str) -> str:
    """Remove URL parts that commonly contain tokens or personal information."""

    parsed_url = urlsplit(url)
    hostname = parsed_url.hostname or ""
    if ":" in hostname:
        hostname = f"[{hostname}]"

    netloc = hostname
    if parsed_url.port is not None:
        netloc = f"{netloc}:{parsed_url.port}"

    redacted_url = SplitResult(
        scheme=parsed_url.scheme,
        netloc=netloc,
        path=parsed_url.path,
        query="",
        fragment="",
    )
    return urlunsplit(redacted_url)


_ROUTE_SEGMENT = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
_MAX_ROUTE_SEGMENTS = 6
_MAX_ROUTE_SEGMENT_DIGITS = 2


def _is_route_fragment(fragment: str) -> bool:
    """Accept fragments shaped like client-side routes, such as ``/login``.

    Hash-routed applications keep the page route in the fragment. Fragments
    can also carry tokens (``#access_token=...`` or ``#/reset/<token>``), so
    only short lowercase segments with at most two digits are accepted; mixed
    case and digit-heavy segments look like encoded values.
    """

    if not fragment.startswith("/"):
        return False
    segments = fragment[1:].split("/")
    if not segments or len(segments) > _MAX_ROUTE_SEGMENTS:
        return False
    return all(
        _ROUTE_SEGMENT.fullmatch(segment) is not None
        and sum(character.isdigit() for character in segment)
        <= _MAX_ROUTE_SEGMENT_DIGITS
        for segment in segments
    )


def url_without_query_keeping_route(url: str) -> str:
    """Like url_without_query_or_fragment, but keep a client-side route."""

    redacted_url = url_without_query_or_fragment(url)
    fragment = urlsplit(url).fragment
    if not _is_route_fragment(fragment):
        return redacted_url
    return f"{redacted_url}#{fragment}"


def origin_from_url(url: str) -> str:
    parsed_url = urlsplit(url)
    scheme = parsed_url.scheme.lower()
    hostname = (parsed_url.hostname or "").lower()

    if not scheme or not hostname:
        raise ValueError(f"URL does not have an origin: {url}")

    port = parsed_url.port
    default_port = 80 if scheme == "http" else 443 if scheme == "https" else None

    if port is None or port == default_port:
        return f"{scheme}://{hostname}"

    return f"{scheme}://{hostname}:{port}"


def url_is_in_scope(url: str, target: TargetScope) -> bool:
    try:
        requested_origin = origin_from_url(url)
    except ValueError:
        return False

    permitted_origins = {
        origin_from_url(str(permitted_origin))
        for permitted_origin in target.permitted_origins
    }
    return requested_origin in permitted_origins
