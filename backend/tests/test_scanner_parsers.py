"""Pure passive discovery and inventory regression tests."""

from webhacking_lab.scanner.crawler import discover_document
from webhacking_lab.scanner.discovery import (
    is_logout_route,
    normalize_discovered_url,
    same_crawl_origin,
)
from webhacking_lab.scanner.javascript_parser import parse_javascript
from webhacking_lab.scanner.openapi_parser import parse_openapi
from webhacking_lab.scanner.robots_parser import parse_robots
from webhacking_lab.scanner.sitemap_parser import parse_sitemap


def test_html_extracts_links_forms_parameters_and_inline_javascript() -> None:
    result = discover_document(
        "https://authorized.example/app/",
        """
        <html><head><title>Authorized demo</title></head><body>
          <a href="/products?id=7&token=do-not-store">Product</a>
          <iframe src="/frame"></iframe>
          <script src="/assets/app.js"></script>
          <script>fetch('/api/items?page=2')</script>
          <form method="post" action="/search">
            <input name="q" value="demo">
            <input name="csrf_token" value="private-value">
            <input type="file" name="attachment">
          </form>
        </body></html>
        """,
        "text/html",
    )
    urls = {item.url for item in result.endpoints}
    assert "https://authorized.example/products?id=7&token=%5BREDACTED%5D" in urls
    assert "https://authorized.example/api/items?page=2" in urls
    assert "https://authorized.example/assets/app.js" in urls
    assert result.title == "Authorized demo"
    parameters = {(item.name, item.location, item.sample_value) for item in result.parameters}
    assert ("id", "query", "7") in parameters
    assert ("token", "query", "[REDACTED]") in parameters
    assert ("q", "form", "demo") in parameters
    assert ("csrf_token", "form", "[REDACTED]") in parameters
    assert ("attachment", "multipart", "") in parameters


def test_javascript_parser_uses_only_static_literal_urls() -> None:
    result = parse_javascript(
        "https://authorized.example/",
        """
        fetch('/api/a?x=1');
        axios.get('/api/b');
        request.open('GET', '/api/c');
        new WebSocket('wss://authorized.example/socket');
        fetch(dynamicValue);
        """,
    )
    assert {item.url for item in result.endpoints} == {
        "https://authorized.example/api/a?x=1",
        "https://authorized.example/api/b",
        "https://authorized.example/api/c",
        "wss://authorized.example/socket",
    }
    assert next(item for item in result.endpoints if item.url.startswith("wss:")).crawlable is False


def test_openapi_extracts_routes_and_input_locations_without_external_servers() -> None:
    result = parse_openapi(
        "https://authorized.example/openapi.json",
        """
        {
          "openapi": "3.1.0",
          "servers": [{"url": "https://outside.example"}],
          "paths": {
            "/products/{id}": {
              "parameters": [{"name": "id", "in": "path"}],
              "get": {"parameters": [{"name": "view", "in": "query"}]},
              "post": {
                "requestBody": {"content": {"application/json": {
                  "schema": {"properties": {"name": {}, "is_admin": {}}}
                }}}
              }
            }
          }
        }
        """,
    )
    assert {(item.method, item.url, item.crawlable) for item in result.endpoints} == {
        ("GET", "https://authorized.example/products/{id}", True),
        ("POST", "https://authorized.example/products/{id}", False),
    }
    assert {(item.name, item.location) for item in result.parameters} == {
        ("id", "path"),
        ("view", "query"),
        ("name", "json"),
        ("is_admin", "json"),
    }


def test_robots_records_disallow_but_never_marks_it_crawlable() -> None:
    result = parse_robots(
        "https://authorized.example/robots.txt",
        "Disallow: /admin\nAllow: /public\nSitemap: /sitemap.xml",
    )
    values = {item.source: item for item in result.endpoints}
    assert values["robots_disallow"].crawlable is False
    assert values["robots_allow"].crawlable is True
    assert values["robots_sitemap"].crawlable is True


def test_discovery_origin_logout_and_malformed_url_rules() -> None:
    assert same_crawl_origin(
        "https://authorized.example/start",
        "https://authorized.example/next",
        False,
    )
    assert not same_crawl_origin(
        "https://authorized.example/start",
        "http://authorized.example/next",
        False,
    )
    assert not same_crawl_origin(
        "https://authorized.example/start",
        "https://outside.example/next",
        True,
    )
    assert is_logout_route("https://authorized.example/account/logout")
    assert normalize_discovered_url("https://authorized.example/", "javascript:alert(1)") is None
    assert (
        normalize_discovered_url("https://authorized.example/", "https://u:p@example.com") is None
    )


def test_sitemap_and_content_dispatch_are_bounded_and_fail_closed() -> None:
    sitemap = parse_sitemap(
        "https://authorized.example/sitemap.xml",
        """
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <url><loc>https://authorized.example/a</loc></url>
          <url><loc>/b?token=private</loc></url>
        </urlset>
        """,
    )
    assert {item.url for item in sitemap.endpoints} == {
        "https://authorized.example/a",
        "https://authorized.example/b?token=%5BREDACTED%5D",
    }
    assert parse_sitemap("https://authorized.example/sitemap.xml", "<broken").endpoints == []
    assert discover_document(
        "https://authorized.example/app.js",
        "axios.get('/api/static')",
        "application/javascript",
    ).endpoints
    assert (
        discover_document(
            "https://authorized.example/data.json",
            '{"openapi":"3.1.0","paths":{}}',
            "application/json",
        ).endpoints
        == []
    )
    assert (
        discover_document(
            "https://authorized.example/image.png",
            "binary",
            "image/png",
        ).endpoints
        == []
    )
