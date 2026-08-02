"""Safe URL normalization and common endpoint discovery helpers."""

from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from webhacking_lab.core.redaction import REDACTED, is_sensitive_name, redact_pairs
from webhacking_lab.scanner.models import DiscoveredParameter


def normalize_discovered_url(base_url: str, candidate: str) -> str | None:
    """Resolve a static URL candidate without performing DNS or network I/O."""

    value = candidate.strip()
    if not value or value.startswith(("#", "javascript:", "data:", "mailto:", "tel:")):
        return None
    try:
        parsed = urlsplit(urljoin(base_url, value))
        parsed_port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https", "ws", "wss"} or parsed.hostname is None:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    hostname = parsed.hostname.lower().rstrip(".")
    default_port = (scheme in {"http", "ws"} and parsed_port == 80) or (
        scheme in {"https", "wss"} and parsed_port == 443
    )
    display_host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = (
        display_host if parsed_port is None or default_port else f"{display_host}:{parsed_port}"
    )
    redacted_query = urlencode(
        [
            (item.name, item.value)
            for item in redact_pairs(parse_qsl(parsed.query, keep_blank_values=True))
        ]
    )
    return urlunsplit((scheme, netloc, parsed.path or "/", redacted_query, ""))


def query_parameters(url: str, source: str) -> list[DiscoveredParameter]:
    """Preserve duplicate query names as observations before repository deduplication."""

    return [
        DiscoveredParameter(
            endpoint_url=url,
            name=name[:300],
            location="query",
            sample_value=REDACTED if is_sensitive_name(name) else value[:500],
            source=source,
        )
        for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True)
        if name
    ]


def same_crawl_origin(seed_url: str, candidate_url: str, include_subdomains: bool) -> bool:
    """Limit traversal to the seed origin or explicitly permitted subdomains."""

    seed = urlsplit(seed_url)
    candidate = urlsplit(candidate_url)
    if (
        candidate.scheme not in {"http", "https"}
        or candidate.scheme != seed.scheme
        or candidate.port != seed.port
    ):
        return False
    if candidate.hostname == seed.hostname:
        return True
    return bool(
        include_subdomains
        and candidate.hostname
        and seed.hostname
        and candidate.hostname.endswith(f".{seed.hostname}")
    )


def is_logout_route(url: str) -> bool:
    """Recognize common session-ending paths that a crawler should never visit by default."""

    path = urlsplit(url).path.lower().rstrip("/")
    return any(path.endswith(value) for value in ("/logout", "/log-out", "/signout", "/sign-out"))
