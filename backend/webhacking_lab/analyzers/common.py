"""Small helpers for passive analyzers."""

from collections.abc import Iterable

from webhacking_lab.http_client.models import NameValue


def header_values(headers: Iterable[NameValue], name: str) -> list[str]:
    """Return all case-insensitive header values without collapsing duplicates."""

    expected = name.lower()
    return [item.value for item in headers if item.name.lower() == expected]


def first_header(headers: Iterable[NameValue], name: str) -> str | None:
    """Return the first matching header value."""

    return next(iter(header_values(headers, name)), None)
