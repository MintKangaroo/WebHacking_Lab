"""Intentionally vulnerable IDOR (broken object-level authorization) target.

WARNING: This service is deliberately insecure. It exists ONLY as a local
training target for the WebHacking Lab platform and attaches solely to the
``isolated_labs`` internal Docker network (no internet, no host ports). Never
deploy it anywhere reachable from an untrusted network.

The ``/notes`` endpoint returns any note by its ``id`` with no ownership
check, so incrementing the identifier past your own notes exposes another
user's private note, which holds the flag.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

FLAG = "FLAG{idor_lets_you_read_another_users_note}"
LISTEN_PORT = 5000

# The "current user" owns notes 1 and 2; note 42 belongs to someone else.
NOTES: dict[str, dict[str, str]] = {
    "1": {"owner": "you", "text": "Remember to water the plants."},
    "2": {"owner": "you", "text": "Draft the quarterly update."},
    "42": {"owner": "admin", "text": f"Master recovery code: {FLAG}"},
}


def lookup_note(note_id: str) -> dict[str, str] | None:
    """Return a note by id with NO authorization check (the vulnerability)."""

    return NOTES.get(note_id)


class LabHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, body: dict[str, object]) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/health":
            self._send_json(200, {"status": "ok"})
            return
        if parsed.path == "/":
            self._send_json(
                200,
                {
                    "message": "Read your notes at /notes?id=1",
                    "your_notes": ["1", "2"],
                },
            )
            return
        if parsed.path == "/notes":
            note_id = parse_qs(parsed.query).get("id", ["1"])[0]
            note = lookup_note(note_id)
            if note is None:
                self._send_json(404, {"error": "note not found"})
                return
            self._send_json(200, {"id": note_id, **note})
            return
        self._send_json(404, {"error": "not found"})

    def log_message(self, *args: object) -> None:
        return


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), LabHandler)  # noqa: S104
    server.serve_forever()


if __name__ == "__main__":
    main()
