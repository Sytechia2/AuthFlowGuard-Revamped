"""Helpers that keep browser activity inside the developer-approved scope."""

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
