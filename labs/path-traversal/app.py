"""Intentionally vulnerable path-traversal training target.

WARNING: This service is deliberately insecure. It exists ONLY as a local
training target for the WebHacking Lab platform and attaches solely to the
``isolated_labs`` internal Docker network (no internet, no host ports). Never
deploy it anywhere reachable from an untrusted network.

The ``/download`` endpoint joins the ``file`` query parameter onto a public
base directory without containment checks, so ``../`` sequences escape the
directory and read arbitrary files (the flag lives outside the public root).
"""

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

LISTEN_PORT = 5000
DEFAULT_PUBLIC_DIR = "/srv/public"


def public_dir() -> str:
    """The document root; the container seeds it, tests override the env var."""

    return os.environ.get("LAB_PUBLIC_DIR", DEFAULT_PUBLIC_DIR)


def resolve_path(file_param: str) -> str:
    """Join the request onto the public dir with NO containment (the bug)."""

    return os.path.normpath(os.path.join(public_dir(), file_param))


class LabHandler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: bytes, content_type: str = "text/plain") -> None:
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/health":
            self._send(200, b"ok")
            return
        if parsed.path == "/":
            self._send(
                200,
                b"Download files with /download?file=welcome.txt",
            )
            return
        if parsed.path == "/download":
            file_param = parse_qs(parsed.query).get("file", ["welcome.txt"])[0]
            target = resolve_path(file_param)
            try:
                with open(target, "rb") as handle:
                    self._send(200, handle.read())
            except (FileNotFoundError, IsADirectoryError, PermissionError) as error:
                self._send(404, f"cannot read file: {error}".encode())
            return
        self._send(404, b"not found")

    def log_message(self, *args: object) -> None:
        return


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), LabHandler)  # noqa: S104
    server.serve_forever()


if __name__ == "__main__":
    main()
