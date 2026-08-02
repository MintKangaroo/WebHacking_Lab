"""Defused sitemap endpoint extraction."""

from defusedxml import ElementTree

from webhacking_lab.scanner.discovery import normalize_discovered_url
from webhacking_lab.scanner.models import DiscoveredEndpoint, DocumentDiscovery


def parse_sitemap(document_url: str, body: str) -> DocumentDiscovery:
    """Extract a bounded set of loc elements from XML sitemap content."""

    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return DocumentDiscovery()
    endpoints: list[DiscoveredEndpoint] = []
    for element in list(root.iter())[:5000]:
        if not element.tag.lower().endswith("loc") or not element.text:
            continue
        url = normalize_discovered_url(document_url, element.text)
        if url is not None:
            endpoints.append(DiscoveredEndpoint(url=url, source="sitemap"))
    return DocumentDiscovery(endpoints=endpoints[:1000])
