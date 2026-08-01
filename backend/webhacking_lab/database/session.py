"""Async SQLAlchemy engine lifecycle and request session dependency."""

from collections.abc import AsyncIterator
from pathlib import Path

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from webhacking_lab.core.config import Settings
from webhacking_lab.database import models as database_models  # noqa: F401
from webhacking_lab.database.base import Base


class Database:
    """Own the SQLAlchemy engine and short-lived async sessions."""

    def __init__(self, database_url: str) -> None:
        self.engine: AsyncEngine = create_async_engine(database_url, pool_pre_ping=True)
        self.session_factory = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

    async def initialize(self) -> None:
        """Create currently registered tables."""

        async with self.engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

    async def close(self) -> None:
        """Dispose pooled connections."""

        await self.engine.dispose()

    async def session(self) -> AsyncIterator[AsyncSession]:
        """Yield a transaction-scoped session."""

        async with self.session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise


def ensure_sqlite_directory(settings: Settings) -> None:
    """Create the parent directory for a file-backed SQLite database."""

    prefix = "sqlite+aiosqlite:///"
    if not settings.database_url.startswith(prefix):
        return
    path_value = settings.database_url.removeprefix(prefix)
    if path_value == ":memory:":
        return
    Path(path_value).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
