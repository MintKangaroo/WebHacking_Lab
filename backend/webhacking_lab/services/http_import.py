"""Safe cURL and HAR import services; imported commands are never executed."""

import base64
import binascii
import json
import shlex
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from webhacking_lab.domain.exceptions import ImportFormatError
from webhacking_lab.http_client.models import ImportedExchange, NormalizedRequest
from webhacking_lab.http_client.request_normalizer import normalize_request, normalize_response

DATA_OPTIONS = {"-d", "--data", "--data-raw", "--data-urlencode", "--data-binary"}
HEADER_OPTIONS = {"-H", "--header"}
METHOD_OPTIONS = {"-X", "--request"}
IGNORED_OPTIONS = {"-s", "--silent", "-S", "--show-error", "--compressed", "-k"}
FORBIDDEN_OPTIONS = {
    "--cert",
    "--key",
    "--proxy",
    "-x",
    "--resolve",
    "--connect-to",
    "--unix-socket",
    "--upload-file",
    "-T",
}


def _option_value(tokens: list[str], index: int, option: str) -> tuple[str, int]:
    if "=" in option and option.startswith("--"):
        return option.split("=", 1)[1], index
    if index + 1 >= len(tokens):
        raise ImportFormatError(f"cURL option {option} requires a value")
    return tokens[index + 1], index + 1


def _append_get_data(url: str, body_parts: list[str]) -> str:
    parsed = urlsplit(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    for part in body_parts:
        query.extend(parse_qsl(part, keep_blank_values=True))
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment)
    )


def import_curl(command: str, *, max_body_bytes: int) -> NormalizedRequest:
    """Parse a bounded cURL command without invoking a shell or subprocess."""

    if len(command.encode("utf-8")) > max_body_bytes * 2:
        raise ImportFormatError("cURL input exceeds the configured size limit")
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as error:
        raise ImportFormatError("cURL command contains invalid quoting") from error
    if not tokens or tokens[0].lower() not in {"curl", "curl.exe"}:
        raise ImportFormatError("Input must begin with curl")

    method: str | None = None
    url: str | None = None
    headers: list[tuple[str, str]] = []
    cookies: list[tuple[str, str]] = []
    body_parts: list[str] = []
    use_get = False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        option_name = token.split("=", 1)[0] if token.startswith("--") else token
        if option_name in FORBIDDEN_OPTIONS:
            raise ImportFormatError(f"cURL option {option_name} is not allowed for import")
        if option_name in METHOD_OPTIONS:
            method, index = _option_value(tokens, index, token)
        elif option_name in HEADER_OPTIONS:
            header, index = _option_value(tokens, index, token)
            if ":" not in header:
                raise ImportFormatError("cURL header must contain a colon")
            name, value = header.split(":", 1)
            headers.append((name.strip(), value.strip()))
        elif option_name in DATA_OPTIONS:
            data, index = _option_value(tokens, index, token)
            if data.startswith("@"):
                raise ImportFormatError("File-backed cURL data is not imported")
            body_parts.append(data)
        elif option_name in {"-b", "--cookie"}:
            cookie_value, index = _option_value(tokens, index, token)
            if cookie_value.startswith("@"):
                raise ImportFormatError("Cookie files are not imported")
            for segment in cookie_value.split(";"):
                if "=" in segment:
                    name, value = segment.strip().split("=", 1)
                    cookies.append((name, value))
        elif option_name in {"--url"}:
            url, index = _option_value(tokens, index, token)
        elif option_name in {"-G", "--get"}:
            use_get = True
        elif option_name in {"-I", "--head"}:
            method = "HEAD"
        elif option_name in IGNORED_OPTIONS:
            if option_name == "-k":
                raise ImportFormatError("Insecure TLS options are not imported")
        elif token.startswith("-"):
            raise ImportFormatError(f"Unsupported cURL option: {option_name}")
        elif url is None:
            url = token
        else:
            raise ImportFormatError("cURL input contains multiple URLs")
        index += 1

    if url is None:
        raise ImportFormatError("cURL URL is required")
    if use_get and body_parts:
        url = _append_get_data(url, body_parts)
        body_parts = []
        method = method or "GET"
    body = "&".join(body_parts)
    return normalize_request(
        method=method or ("POST" if body_parts else "GET"),
        url=url,
        headers=headers,
        cookies=cookies,
        body=body,
        max_body_bytes=max_body_bytes,
    )


def _pairs(value: Any) -> list[tuple[str, str]]:
    if not isinstance(value, list):
        return []
    return [
        (item["name"], str(item.get("value", "")))
        for item in value
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    ]


def _har_body(content: Any) -> str:
    if not isinstance(content, dict):
        return ""
    text = content.get("text", "")
    if not isinstance(text, str):
        return ""
    if content.get("encoding") != "base64":
        return text
    try:
        return base64.b64decode(text, validate=True).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError) as error:
        raise ImportFormatError("HAR response contains invalid base64") from error


def import_har(
    payload: str,
    *,
    max_har_bytes: int,
    max_entries: int,
    max_request_bytes: int,
    max_response_bytes: int,
) -> list[ImportedExchange]:
    """Parse a bounded HAR 1.x document into redacted exchanges."""

    if len(payload.encode("utf-8")) > max_har_bytes:
        raise ImportFormatError("HAR exceeds the configured archive size limit")
    try:
        document = json.loads(payload)
    except json.JSONDecodeError as error:
        raise ImportFormatError("HAR is not valid JSON") from error
    entries = document.get("log", {}).get("entries") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        raise ImportFormatError("HAR log.entries must be an array")
    if len(entries) > max_entries:
        raise ImportFormatError("HAR contains too many entries")

    exchanges: list[ImportedExchange] = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
            raise ImportFormatError("HAR entry is missing a request object")
        request_data = entry["request"]
        post_data = request_data.get("postData", {})
        body = post_data.get("text", "") if isinstance(post_data, dict) else ""
        headers = _pairs(request_data.get("headers"))
        if (
            isinstance(post_data, dict)
            and post_data.get("mimeType")
            and not any(name.lower() == "content-type" for name, _ in headers)
        ):
            headers.append(("Content-Type", str(post_data["mimeType"])))
        query_items = _pairs(request_data.get("queryString"))
        request = normalize_request(
            method=str(request_data.get("method", "GET")),
            url=str(request_data.get("url", "")),
            headers=headers,
            cookies=_pairs(request_data.get("cookies")),
            body=str(body),
            query=query_items or None,
            max_body_bytes=max_request_bytes,
        )

        response = None
        response_data = entry.get("response")
        if isinstance(response_data, dict) and int(response_data.get("status", 0)) >= 100:
            response_headers = _pairs(response_data.get("headers"))
            content = response_data.get("content", {})
            if (
                isinstance(content, dict)
                and content.get("mimeType")
                and not any(name.lower() == "content-type" for name, _ in response_headers)
            ):
                response_headers.append(("Content-Type", str(content["mimeType"])))
            elapsed_ms = (
                float(entry["time"]) if isinstance(entry.get("time"), (int, float)) else None
            )
            response = normalize_response(
                status_code=int(response_data["status"]),
                reason=str(response_data.get("statusText", "")),
                headers=response_headers,
                cookies=_pairs(response_data.get("cookies")),
                body=_har_body(content),
                elapsed_ms=elapsed_ms,
                max_body_bytes=max_response_bytes,
            )
        exchanges.append(ImportedExchange(request=request, response=response))
    return exchanges
