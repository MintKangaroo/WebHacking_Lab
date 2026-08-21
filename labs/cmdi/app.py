"""Intentionally vulnerable command-injection training target.

WARNING: This service is deliberately insecure. It exists ONLY as a local
training target for the WebHacking Lab platform and attaches solely to the
``isolated_labs`` internal Docker network (no internet, no host ports). Never
deploy it anywhere reachable from an untrusted network.

The ``/ping`` endpoint concatenates the ``host`` query parameter into a shell
command executed with ``shell``-style semantics, so a ``;`` or ``$(...)``
payload runs arbitrary commands and can read the ``FLAG`` from the process
environment.
"""

import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

FLAG = "FLAG{command_injection_via_unsanitized_shell_input}"
LISTEN_PORT = 5000


def run_ping(host: str) -> str:
    """Run the diagnostic command with unsanitized input (the vulnerability)."""

    # VULNERABLE: untrusted input is concatenated into the shell command.
    command = "echo pinging " + host
    completed = subprocess.run(  # noqa: S603 - deliberate command-injection sink
        ["/bin/sh", "-c", command],
        capture_output=True,
        text=True,
        timeout=5,
        env={"FLAG": FLAG, "PATH": "/usr/bin:/bin"},
        check=False,
    )
    return completed.stdout + completed.stderr


class LabHandler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/health":
            self._send(200, "ok")
            return
        if parsed.path == "/":
            self._send(200, "Check reachability with /ping?host=localhost")
            return
        if parsed.path == "/ping":
            host = parse_qs(parsed.query).get("host", ["localhost"])[0]
            self._send(200, run_ping(host))
            return
        self._send(404, "not found")

    def log_message(self, *args: object) -> None:
        return


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), LabHandler)  # noqa: S104
    server.serve_forever()


if __name__ == "__main__":
    main()
