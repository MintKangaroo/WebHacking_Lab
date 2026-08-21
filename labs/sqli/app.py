"""Intentionally vulnerable SQL-injection training target.

WARNING: This service is deliberately insecure. It exists ONLY as a local
training target for the WebHacking Lab platform and attaches solely to the
``isolated_labs`` internal Docker network (no internet, no host ports). Never
deploy it anywhere reachable from an untrusted network.

The ``/products`` endpoint concatenates the ``id`` query parameter directly
into a SQL statement, so a UNION-based injection can read the ``secrets`` table
and recover the flag.
"""

import html
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

FLAG = "FLAG{sqli_union_select_reveals_the_secret}"
LISTEN_PORT = 5000


def build_connection() -> sqlite3.Connection:
    """Create and seed an in-memory training database."""

    connection = sqlite3.connect(":memory:", check_same_thread=False)
    connection.executescript(
        """
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price TEXT);
        CREATE TABLE secrets (name TEXT, flag TEXT);
        INSERT INTO products (id, name, price) VALUES
            (1, 'Training Widget', '9.99'),
            (2, 'Practice Gadget', '14.50'),
            (3, 'Sample Gizmo', '3.25');
        """
    )
    connection.execute("INSERT INTO secrets (name, flag) VALUES (?, ?)", ("flag", FLAG))
    connection.commit()
    return connection


def product_query(connection: sqlite3.Connection, id_param: str) -> list[tuple[object, ...]]:
    """Run the deliberately unsafe product lookup (string-concatenated SQL)."""

    statement = "SELECT id, name, price FROM products WHERE id = " + id_param  # noqa: S608
    return list(connection.execute(statement).fetchall())


class LabHandler(BaseHTTPRequestHandler):
    # NOTE: ``connection`` is reserved by ``BaseHTTPRequestHandler`` for the
    # client socket, so the training database uses a distinct attribute name.
    db_connection: sqlite3.Connection

    def _send(self, status: int, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 (stdlib handler contract)
        parsed = urlsplit(self.path)
        if parsed.path == "/health":
            self._send(200, "ok")
            return
        if parsed.path == "/":
            self._send(
                200,
                "<h1>SQLi training lab</h1>"
                "<p>Try <code>/products?id=1</code>. The flag lives in a "
                "<code>secrets</code> table.</p>",
            )
            return
        if parsed.path == "/products":
            id_param = parse_qs(parsed.query).get("id", ["1"])[0]
            try:
                rows = product_query(self.db_connection, id_param)
            except sqlite3.Error as error:
                # Error-based signal: the raw database error is reflected.
                self._send(500, f"<pre>SQL error: {html.escape(str(error))}</pre>")
                return
            listing = "".join(
                f"<li>{html.escape(str(row[0]))}: {html.escape(str(row[1]))} "
                f"(${html.escape(str(row[2]))})</li>"
                for row in rows
            )
            self._send(200, f"<ul>{listing or '<li>no products</li>'}</ul>")
            return
        self._send(404, "<p>not found</p>")

    def log_message(self, *args: object) -> None:  # noqa: D401 (silence default logging)
        return


def main() -> None:
    LabHandler.db_connection = build_connection()
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), LabHandler)  # noqa: S104
    server.serve_forever()


if __name__ == "__main__":
    main()
