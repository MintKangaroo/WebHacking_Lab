"""robots.txt inventory extraction without overriding scope policy."""

from webhacking_lab.scanner.discovery import normalize_discovered_url
from webhacking_lab.scanner.models import DiscoveredEndpoint, DocumentDiscovery


def parse_robots(document_url: str, body: str) -> DocumentDiscovery:
    """Record Allow, Disallow, and Sitemap targets but never crawl Disallow entries."""

    endpoints: list[DiscoveredEndpoint] = []
    for line in body.splitlines()[:5000]:
        key, separator, raw_value = line.partition(":")
        if not separator:
            continue
        directive = key.strip().lower()
        value = raw_value.strip()
        if directive not in {"allow", "disallow", "sitemap"} or not value:
            continue
        url = normalize_discovered_url(document_url, value)
        if url is None:
            continue
        endpoints.append(
            DiscoveredEndpoint(
                url=url,
                source=f"robots_{directive}",
                crawlable=directive in {"allow", "sitemap"},
            )
        )
    return DocumentDiscovery(endpoints=endpoints)
