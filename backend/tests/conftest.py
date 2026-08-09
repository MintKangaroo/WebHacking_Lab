"""Shared FastAPI test fixtures."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from webhacking_lab.api.app import create_app
from webhacking_lab.core.config import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Return an isolated in-memory configuration."""

    return Settings(
        environment="test",
        database_url="sqlite+aiosqlite:///:memory:",
        cors_origins=["http://testserver"],
        code_upload_root=str(tmp_path / "code_uploads"),
        max_code_archive_bytes=1_000_000,
        max_code_extracted_bytes=500_000,
        max_code_files=100,
        max_code_single_file_bytes=200_000,
    )


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    """Yield a client with lifespan events enabled."""

    with TestClient(create_app(settings)) as test_client:
        yield test_client
