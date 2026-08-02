"""HTML form and navigation extraction without browser execution."""

from bs4 import BeautifulSoup

from webhacking_lab.core.redaction import REDACTED, is_sensitive_name
from webhacking_lab.scanner.discovery import normalize_discovered_url, query_parameters
from webhacking_lab.scanner.models import (
    DiscoveredEndpoint,
    DiscoveredParameter,
    DocumentDiscovery,
)


def parse_html(base_url: str, body: str) -> DocumentDiscovery:
    """Extract links, frames, scripts, forms, fields, and a display title."""

    soup = BeautifulSoup(body, "lxml")
    endpoints: list[DiscoveredEndpoint] = []
    parameters: list[DiscoveredParameter] = []
    for tag_name, attribute, source in (
        ("a", "href", "html_link"),
        ("iframe", "src", "html_iframe"),
        ("script", "src", "html_script"),
    ):
        for tag in soup.find_all(tag_name):
            raw_value = tag.get(attribute)
            if not isinstance(raw_value, str):
                continue
            url = normalize_discovered_url(base_url, raw_value)
            if url is None:
                continue
            endpoints.append(
                DiscoveredEndpoint(
                    url=url,
                    source=source,
                    crawlable=not url.startswith(("ws://", "wss://")),
                )
            )
            parameters.extend(query_parameters(url, source))

    for form in soup.find_all("form"):
        raw_action = form.get("action")
        action = normalize_discovered_url(
            base_url,
            raw_action if isinstance(raw_action, str) and raw_action else base_url,
        )
        if action is None:
            continue
        raw_method = form.get("method")
        method = raw_method.upper() if isinstance(raw_method, str) else "GET"
        method = method if method in {"GET", "POST"} else "GET"
        endpoints.append(
            DiscoveredEndpoint(
                url=action,
                method=method,
                source="html_form",
                crawlable=method == "GET",
            )
        )
        parameters.extend(query_parameters(action, "html_form"))
        encoding = form.get("enctype")
        multipart = isinstance(encoding, str) and "multipart/form-data" in encoding.lower()
        for field in form.find_all(["input", "textarea", "select", "button"]):
            name = field.get("name")
            if not isinstance(name, str) or not name:
                continue
            field_type = field.get("type")
            location = (
                "multipart"
                if multipart or (isinstance(field_type, str) and field_type.lower() == "file")
                else ("query" if method == "GET" else "form")
            )
            raw_sample = field.get("value")
            parameters.append(
                DiscoveredParameter(
                    endpoint_url=action,
                    name=name[:300],
                    location=location,
                    sample_value=(
                        REDACTED
                        if is_sensitive_name(name)
                        else (raw_sample[:500] if isinstance(raw_sample, str) else "")
                    ),
                    source="html_form",
                )
            )
    title = soup.title.string.strip()[:300] if soup.title and soup.title.string else None
    return DocumentDiscovery(endpoints=endpoints, parameters=parameters, title=title)
