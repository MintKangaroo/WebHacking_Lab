"""Conservative static JavaScript URL extraction; scripts are never executed."""

import re

from webhacking_lab.scanner.discovery import normalize_discovered_url, query_parameters
from webhacking_lab.scanner.models import DiscoveredEndpoint, DocumentDiscovery

STATIC_URL_PATTERNS = (
    re.compile(r"\bfetch\s*\(\s*['\"]([^'\"]{1,2048})['\"]"),
    re.compile(
        r"\baxios(?:\.(?:get|post|put|patch|delete)|\s*\()\s*\(?\s*['\"]([^'\"]{1,2048})['\"]"
    ),
    re.compile(
        r"\.open\s*\(\s*['\"](?:GET|POST|PUT|PATCH|DELETE)['\"]\s*,\s*['\"]([^'\"]{1,2048})['\"]",
        re.IGNORECASE,
    ),
    re.compile(r"\bnew\s+WebSocket\s*\(\s*['\"]([^'\"]{1,2048})['\"]"),
)


def parse_javascript(base_url: str, body: str) -> DocumentDiscovery:
    """Return only literal fetch, Axios, XHR, and WebSocket targets."""

    endpoints: list[DiscoveredEndpoint] = []
    parameters = []
    for pattern in STATIC_URL_PATTERNS:
        for match in pattern.finditer(body):
            url = normalize_discovered_url(base_url, match.group(1))
            if url is None:
                continue
            endpoints.append(
                DiscoveredEndpoint(
                    url=url,
                    source="javascript_static",
                    crawlable=url.startswith(("http://", "https://")),
                )
            )
            parameters.extend(query_parameters(url, "javascript_static"))
    return DocumentDiscovery(endpoints=endpoints, parameters=parameters)
