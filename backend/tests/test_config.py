"""Safety configuration tests."""

import pytest
from pydantic import ValidationError

from webhacking_lab.core.config import Settings


def test_settings_reject_unbounded_concurrency() -> None:
    with pytest.raises(ValidationError):
        Settings(default_target_concurrency=100)


def test_settings_reject_large_response_limit() -> None:
    with pytest.raises(ValidationError):
        Settings(max_response_bytes=100 * 1024 * 1024)
