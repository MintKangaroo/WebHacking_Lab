"""Regression tests proving the SQLi training lab stays exploitable."""

import importlib.util
import sys
from pathlib import Path
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
