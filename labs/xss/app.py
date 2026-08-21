"""Intentionally vulnerable reflected-XSS training target.

WARNING: This service is deliberately insecure. It exists ONLY as a local
training target for the WebHacking Lab platform and attaches solely to the
``isolated_labs`` internal Docker network (no internet, no host ports). Never
deploy it anywhere reachable from an untrusted network.

The ``/search`` endpoint reflects the ``q`` query parameter into the HTML
response without any escaping, so a ``<script>`` payload executes in the
victim's browser and can read the ``SESSION_FLAG`` embedded on the page.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

FLAG = "FLAG{reflected_xss_runs_in_the_victim_session}"
LISTEN_PORT = 5000

# A real reflected-XSS payload would exfiltrate this session secret.
PAGE_HEADER = f'<script>const SESSION_FLAG = "{FLAG}";</script><h1>Mini Search</h1>'


def render_search(query: str) -> str:
    """Reflect the query straight into the page (deliberately unescaped)."""

    return f"{PAGE_HEADER}<p>Results for: {query}</p>"


class LabHandler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/health":
            self._send(200, "ok")
            return
        if parsed.path == "/":
            self._send(
                200,
                f'{PAGE_HEADER}<form action="/search">'
                '<input name="q" placeholder="search"><button>Search</button></form>',
            )
            return
        if parsed.path == "/search":
            query = parse_qs(parsed.query).get("q", [""])[0]
            self._send(200, render_search(query))
            return
        self._send(404, "<p>not found</p>")

    def log_message(self, *args: object) -> None:
        return


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), LabHandler)  # noqa: S104
    server.serve_forever()


if __name__ == "__main__":
    main()
