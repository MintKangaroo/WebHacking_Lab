"""HTTP request and response normalization without network access."""

import ipaddress
import re
from hashlib import sha256
from urllib.parse import parse_qsl, urlsplit

from webhacking_lab.core.redaction import redact_body, redact_pairs
from webhacking_lab.domain.exceptions import ImportFormatError
from webhacking_lab.http_client.models import (
    NormalizedRequest,
    NormalizedResponse,
    RedirectHop,
)


def normalize_hostname(hostname: str) -> str:
    """Normalize a DNS hostname or IP literal without resolving it."""

    candidate = hostname.strip().rstrip(".").lower()
    if not candidate:
        raise ImportFormatError("URL hostname is required")
    if "%" in candidate:
        raise ImportFormatError("Scoped IP zone identifiers are not supported")
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        pass
    try:
        normalized = candidate.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ImportFormatError("URL hostname is not valid IDNA") from error
    label_pattern = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
    if len(normalized) > 253 or any(
        not label_pattern.fullmatch(label) for label in normalized.split(".")
    ):
        raise ImportFormatError("URL hostname contains invalid DNS labels")
    return normalized


def content_type_and_charset(headers: list[tuple[str, str]]) -> tuple[str | None, str]:
    """Extract media type and charset from the last Content-Type header."""

    value = next(
        (
            header_value
            for name, header_value in reversed(headers)
            if name.lower() == "content-type"
        ),
        None,
    )
    if value is None:
        return None, "utf-8"
    sections = [section.strip() for section in value.split(";")]
    charset = "utf-8"
    for section in sections[1:]:
        if section.lower().startswith("charset="):
            charset = section.split("=", 1)[1].strip("\"'") or "utf-8"
    return sections[0].lower(), charset


def parse_cookie_headers(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Extract duplicate cookie names from request Cookie headers."""

    cookies: list[tuple[str, str]] = []
    for header_name, header_value in headers:
        if header_name.lower() != "cookie":
            continue
        for segment in header_value.split(";"):
            if "=" in segment:
                name, value = segment.strip().split("=", 1)
                if name:
                    cookies.append((name, value))
    return cookies


def normalize_request(
    *,
    method: str,
    url: str,
    headers: list[tuple[str, str]] | None = None,
    cookies: list[tuple[str, str]] | None = None,
    body: str = "",
    query: list[tuple[str, str]] | None = None,
    max_body_bytes: int,
) -> NormalizedRequest:
    """Normalize and redact a request while preserving multimap ordering."""

    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as error:
        raise ImportFormatError("URL contains an invalid port or authority") from error
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ImportFormatError("Only http and https URLs are supported")
    if parsed.username is not None or parsed.password is not None:
        raise ImportFormatError("URLs containing user information are rejected")
    if parsed.hostname is None:
        raise ImportFormatError("URL hostname is required")
    if len(body.encode("utf-8")) > max_body_bytes:
        raise ImportFormatError("Request body exceeds the configured size limit")

    normalized_headers = headers or []
    content_type, charset = content_type_and_charset(normalized_headers)
    query_items = query if query is not None else parse_qsl(parsed.query, keep_blank_values=True)
    cookie_items = (cookies or []) + parse_cookie_headers(normalized_headers)
    scheme = parsed.scheme.lower()
    path = parsed.path or "/"

    return NormalizedRequest(
        method=method,
        scheme=scheme,
        host=normalize_hostname(parsed.hostname),
        port=port or (80 if scheme == "http" else 443),
        path=path,
        query=redact_pairs(query_items),
        headers=redact_pairs(normalized_headers, headers=True),
        cookies=redact_pairs(cookie_items, mask_all=True),
        body=redact_body(body, content_type),
        content_type=content_type,
        character_encoding=charset,
    )


def normalize_response(
    *,
    status_code: int,
    reason: str = "",
    headers: list[tuple[str, str]] | None = None,
    cookies: list[tuple[str, str]] | None = None,
    body: str = "",
    elapsed_ms: float | None = None,
    redirect_history: list[RedirectHop] | None = None,
    max_body_bytes: int,
) -> NormalizedResponse:
    """Normalize and redact an imported response."""

    if len(body.encode("utf-8")) > max_body_bytes:
        raise ImportFormatError("Response body exceeds the configured size limit")
    normalized_headers = headers or []
    content_type, charset = content_type_and_charset(normalized_headers)
    redacted_body = redact_body(body, content_type)
    digest = sha256(redacted_body.encode("utf-8")).hexdigest()
    return NormalizedResponse(
        status_code=status_code,
        reason=reason,
        headers=redact_pairs(normalized_headers, headers=True),
        cookies=redact_pairs(cookies or [], mask_all=True),
        body=redacted_body,
        content_type=content_type,
        character_encoding=charset,
        elapsed_ms=elapsed_ms,
        redirect_history=redirect_history or [],
        body_hash=digest,
        normalized_body_hash=digest,
    )


def render_raw_request(request: NormalizedRequest) -> str:
    """Render a normalized redacted request for UI preview and persistence."""

    from urllib.parse import urlencode

    query = urlencode([(item.name, item.value) for item in request.query])
    target = request.path + (f"?{query}" if query else "")
    default_port = 80 if request.scheme == "http" else 443
    display_host = f"[{request.host}]" if ":" in request.host else request.host
    host = display_host if request.port == default_port else f"{display_host}:{request.port}"
    header_lines = [f"{item.name}: {item.value}" for item in request.headers]
    if not any(item.name.lower() == "host" for item in request.headers):
        header_lines.insert(0, f"Host: {host}")
    sections = [f"{request.method} {target} HTTP/1.1", *header_lines, ""]
    if request.body:
        sections.extend(["", request.body])
    return "\r\n".join(sections)
