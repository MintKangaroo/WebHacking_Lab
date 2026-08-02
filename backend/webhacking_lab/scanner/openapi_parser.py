"""Bounded OpenAPI path and parameter inventory extraction."""

import json
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from webhacking_lab.scanner.discovery import normalize_discovered_url
from webhacking_lab.scanner.models import (
    DiscoveredEndpoint,
    DiscoveredParameter,
    DocumentDiscovery,
)

HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})


def _api_base(document_url: str) -> str:
    parsed = urlsplit(document_url)
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


def _parameters(
    raw_parameters: Any,
    endpoint_url: str,
) -> list[DiscoveredParameter]:
    if not isinstance(raw_parameters, list):
        return []
    result: list[DiscoveredParameter] = []
    for value in raw_parameters[:200]:
        if not isinstance(value, dict):
            continue
        name = value.get("name")
        location = value.get("in")
        if not isinstance(name, str) or location not in {"query", "path", "header", "cookie"}:
            continue
        result.append(
            DiscoveredParameter(
                endpoint_url=endpoint_url,
                name=name[:300],
                location=location,
                source="openapi",
            )
        )
    return result


def parse_openapi(document_url: str, body: str) -> DocumentDiscovery:
    """Extract same-origin routes from an OpenAPI JSON document."""

    try:
        document = json.loads(body)
    except json.JSONDecodeError:
        return DocumentDiscovery()
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        return DocumentDiscovery()
    endpoints: list[DiscoveredEndpoint] = []
    parameters: list[DiscoveredParameter] = []
    for path, path_item in list(document["paths"].items())[:500]:
        if not isinstance(path, str) or not isinstance(path_item, dict):
            continue
        endpoint_url = normalize_discovered_url(_api_base(document_url), path)
        if endpoint_url is None:
            continue
        parameters.extend(_parameters(path_item.get("parameters"), endpoint_url))
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            endpoints.append(
                DiscoveredEndpoint(
                    url=endpoint_url,
                    method=method.upper(),
                    source="openapi",
                    crawlable=method.lower() in {"get", "head", "options"},
                )
            )
            parameters.extend(_parameters(operation.get("parameters"), endpoint_url))
            body_definition = operation.get("requestBody")
            if not isinstance(body_definition, dict):
                continue
            content = body_definition.get("content")
            if not isinstance(content, dict):
                continue
            for media_type, media in list(content.items())[:10]:
                if not isinstance(media, dict) or not isinstance(media.get("schema"), dict):
                    continue
                properties = media["schema"].get("properties")
                if not isinstance(properties, dict):
                    continue
                location = "multipart" if "multipart" in str(media_type) else "json"
                parameters.extend(
                    DiscoveredParameter(
                        endpoint_url=endpoint_url,
                        name=str(name)[:300],
                        location=location,
                        source="openapi",
                    )
                    for name in list(properties)[:200]
                )
    return DocumentDiscovery(endpoints=endpoints, parameters=parameters)
