"""Pure response-document discovery router for the passive crawler."""

from urllib.parse import urlsplit

from webhacking_lab.scanner.form_parser import parse_html
from webhacking_lab.scanner.javascript_parser import parse_javascript
from webhacking_lab.scanner.models import DocumentDiscovery
from webhacking_lab.scanner.openapi_parser import parse_openapi
from webhacking_lab.scanner.robots_parser import parse_robots
from webhacking_lab.scanner.sitemap_parser import parse_sitemap


def discover_document(url: str, body: str, content_type: str | None) -> DocumentDiscovery:
    """Dispatch bounded parsing by public content type and well-known filename."""

    path = urlsplit(url).path.lower()
    media_type = (content_type or "").lower()
    if path.endswith("/robots.txt") or path == "/robots.txt":
        return parse_robots(url, body)
    if "xml" in media_type or path.endswith(".xml"):
        return parse_sitemap(url, body)
    if path.endswith(("openapi.json", "swagger.json")):
        return parse_openapi(url, body)
    if "javascript" in media_type or path.endswith((".js", ".mjs")):
        return parse_javascript(url, body)
    if "html" in media_type or "<html" in body[:1000].lower():
        html = parse_html(url, body)
        inline_javascript = parse_javascript(url, body)
        return DocumentDiscovery(
            endpoints=[*html.endpoints, *inline_javascript.endpoints],
            parameters=[*html.parameters, *inline_javascript.parameters],
            title=html.title,
        )
    if "json" in media_type and ('"openapi"' in body[:500] or '"swagger"' in body[:500]):
        return parse_openapi(url, body)
    return DocumentDiscovery()
