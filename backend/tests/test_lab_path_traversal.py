"""Regression tests proving the path-traversal training lab stays exploitable."""

import importlib.util
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from types import ModuleType

import pytest

_LAB_APP = Path(__file__).resolve().parents[2] / "labs" / "path-traversal" / "app.py"


def _load_lab_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("lab_path_traversal_app", _LAB_APP)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


lab = _load_lab_module()
FLAG = "FLAG{path_traversal_reads_outside_the_public_root}"


@pytest.fixture
def lab_base_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    public = tmp_path / "public"
    secret = tmp_path / "secret"
    public.mkdir()
    secret.mkdir()
    (public / "welcome.txt").write_text("hello from the public root\n")
    (public / "notes.txt").write_text("rotate the service credentials\n")
    (secret / "flag.txt").write_text(f"{FLAG}\n")
    monkeypatch.setenv("LAB_PUBLIC_DIR", str(public))

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


def _get(base_url: str, file_param: str) -> tuple[int, str]:
    url = f"{base_url}/download?" + urllib.parse.urlencode({"file": file_param})
    try:
        with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310 - loopback
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


def test_http_serves_a_public_file(lab_base_url: str) -> None:
    status, body = _get(lab_base_url, "notes.txt")
    assert status == 200
    assert "rotate the service credentials" in body


def test_http_traversal_reads_the_secret_flag(lab_base_url: str) -> None:
    status, body = _get(lab_base_url, "../secret/flag.txt")
    assert status == 200
    assert FLAG in body


def test_http_missing_file_is_not_found(lab_base_url: str) -> None:
    status, _ = _get(lab_base_url, "nope.txt")
    assert status == 404
