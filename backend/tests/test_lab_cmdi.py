"""Regression tests proving the command-injection training lab stays exploitable."""

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

_LAB_APP = Path(__file__).resolve().parents[2] / "labs" / "cmdi" / "app.py"


def _load_lab_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("lab_cmdi_app", _LAB_APP)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


lab = _load_lab_module()


def test_normal_host_is_echoed() -> None:
    assert "pinging localhost" in lab.run_ping("localhost")


def test_injection_leaks_the_flag_from_the_environment() -> None:
    assert lab.FLAG in lab.run_ping("localhost; echo $FLAG")


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


def _get(base_url: str, host: str) -> str:
    url = f"{base_url}/ping?" + urllib.parse.urlencode({"host": host})
    with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310 - loopback
        return response.read().decode()


def test_http_normal_request_echoes_the_host(lab_base_url: str) -> None:
    assert "pinging localhost" in _get(lab_base_url, "localhost")


def test_http_injection_runs_a_second_command(lab_base_url: str) -> None:
    assert lab.FLAG in _get(lab_base_url, "localhost; echo $FLAG")
