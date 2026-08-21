"""Regression tests proving the IDOR training lab stays exploitable."""

import importlib.util
import json
import sys
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from types import ModuleType

import pytest

_LAB_APP = Path(__file__).resolve().parents[2] / "labs" / "idor" / "app.py"


def _load_lab_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("lab_idor_app", _LAB_APP)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


lab = _load_lab_module()


def test_lookup_has_no_ownership_check() -> None:
    assert lab.lookup_note("1")["owner"] == "you"
    assert lab.FLAG in lab.lookup_note("42")["text"]
    assert lab.lookup_note("999") is None


@pytest.fixture
def lab_base_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), lab.LabHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _get(base_url: str, path: str) -> tuple[int, dict[str, object]]:
    try:
        with urllib.request.urlopen(base_url + path, timeout=5) as response:  # noqa: S310
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode())


def test_http_own_note_is_returned(lab_base_url: str) -> None:
    status, body = _get(lab_base_url, "/notes?id=1")
    assert status == 200
    assert body["owner"] == "you"


def test_http_other_users_note_leaks_the_flag(lab_base_url: str) -> None:
    status, body = _get(lab_base_url, "/notes?id=42")
    assert status == 200
    assert lab.FLAG in str(body["text"])


def test_http_unknown_note_is_not_found(lab_base_url: str) -> None:
    status, _ = _get(lab_base_url, "/notes?id=999")
    assert status == 404
