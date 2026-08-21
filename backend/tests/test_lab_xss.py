"""Regression tests proving the reflected-XSS training lab stays exploitable."""

import importlib.util
import sys
import urllib.parse
import urllib.request
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from types import ModuleType

import pytest

_LAB_APP = Path(__file__).resolve().parents[2] / "labs" / "xss" / "app.py"


def _load_lab_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("lab_xss_app", _LAB_APP)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


lab = _load_lab_module()


def test_render_reflects_the_query_without_escaping() -> None:
    body = lab.render_search("<script>alert(1)</script>")
    assert "<script>alert(1)</script>" in body
    assert "&lt;script&gt;" not in body


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


def _get(base_url: str, path: str) -> str:
    with urllib.request.urlopen(base_url + path, timeout=5) as response:  # noqa: S310 - loopback
        return response.read().decode()


def test_http_search_reflects_script_payload_raw(lab_base_url: str) -> None:
    payload = urllib.parse.quote("<script>steal()</script>")
    body = _get(lab_base_url, f"/search?q={payload}")
    assert "<script>steal()</script>" in body


def test_http_page_exposes_the_session_flag(lab_base_url: str) -> None:
    body = _get(lab_base_url, "/search?q=hi")
    assert lab.FLAG in body
