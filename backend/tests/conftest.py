"""Shared FastAPI test fixtures."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from webhacking_lab.api.app import create_app
from webhacking_lab.core.config import Settings


@pytest.fixture
def settings() -> Settings:
    """Return an isolated in-memory configuration."""

    return Settings(
        environment="test",
        database_url="sqlite+aiosqlite:///:memory:",
        cors_origins=["http://testserver"],
    )


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    """Yield a client with lifespan events enabled."""

    with TestClient(create_app(settings)) as test_client:
        yield test_client
