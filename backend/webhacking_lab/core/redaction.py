"""Deterministic masking for HTTP data, logs, and persisted artifacts."""

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import parse_qsl, urlencode

from webhacking_lab.http_client.models import NameValue

REDACTED = "[REDACTED]"
SENSITIVE_NAMES = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "api-key",
        "apikey",
        "access-token",
        "x-access-token",
        "password",
        "passwd",
        "secret",
        "client-secret",
        "client_secret",
        "token",
        "access_token",
        "refresh_token",
        "session",
        "sessionid",
        "csrf_token",
    }
)
COOKIE_HEADERS = frozenset({"cookie", "set-cookie"})
ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|secret)"
    r"(\s*[:=]\s*)([^&\s,;]+)"
)


def is_sensitive_name(name: str) -> bool:
    """Return whether a key should be masked by default."""

    normalized = name.strip().lower().replace("_", "-")
    return normalized in SENSITIVE_NAMES or normalized.endswith(("-token", "-secret", "-key"))


def redact_cookie_string(value: str) -> str:
    """Preserve cookie names and attributes while removing values."""

    parts: list[str] = []
    for index, segment in enumerate(value.split(";")):
        stripped = segment.strip()
        if "=" not in stripped:
            parts.append(stripped)
            continue
        name, cookie_value = stripped.split("=", 1)
        attribute = name.lower() in {
            "path",
            "domain",
            "expires",
            "max-age",
            "samesite",
        }
        if index > 0 and attribute:
            parts.append(f"{name}={cookie_value}")
        else:
            parts.append(f"{name}={REDACTED}")
    return "; ".join(parts)


def redact_pairs(
    values: Sequence[tuple[str, str] | NameValue],
    *,
    headers: bool = False,
    mask_all: bool = False,
) -> list[NameValue]:
    """Mask sensitive multimap values without collapsing duplicates."""

    result: list[NameValue] = []
    for item in values:
        name, value = (item.name, item.value) if isinstance(item, NameValue) else item
        normalized_name = name.strip().lower()
        if headers and normalized_name in COOKIE_HEADERS:
            result.append(NameValue(name=name, value=redact_cookie_string(value), redacted=True))
        elif mask_all or is_sensitive_name(name):
            result.append(NameValue(name=name, value=REDACTED, redacted=True))
        else:
            result.append(NameValue(name=name, value=value, redacted=False))
    return result


def redact_mapping(value: Any, key: str | None = None) -> Any:
    """Recursively mask secret-shaped keys in JSON-compatible data."""

    if key is not None and is_sensitive_name(key):
        return REDACTED
    if isinstance(value, Mapping):
        return {
            str(item_key): redact_mapping(item_value, str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [redact_mapping(item) for item in value]
    return value


def redact_text(value: str) -> str:
    """Mask common key/value secrets in otherwise unstructured text."""

    return ASSIGNMENT_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}",
        value,
    )


def redact_body(body: str, content_type: str | None) -> str:
    """Redact JSON, form, or text bodies without executing content."""

    media_type = (content_type or "").split(";", 1)[0].strip().lower()
    if media_type == "application/json" or media_type.endswith("+json"):
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return redact_text(body)
        return json.dumps(redact_mapping(parsed), ensure_ascii=False, separators=(",", ":"))
    if media_type == "application/x-www-form-urlencoded":
        pairs = redact_pairs(parse_qsl(body, keep_blank_values=True))
        return urlencode([(item.name, item.value) for item in pairs])
    return redact_text(body)
