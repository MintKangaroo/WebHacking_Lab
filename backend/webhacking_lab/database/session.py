"""Async SQLAlchemy engine lifecycle and request session dependency."""

from collections.abc import AsyncIterator
from pathlib import Path

from sqlalchemy import Connection, inspect
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
        """Create tables and bridge legacy Compose schemas without deleting data."""

        async with self.engine.begin() as connection:
            await connection.run_sync(_bridge_legacy_code_project_authorization)
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


def _bridge_legacy_code_project_authorization(connection: Connection) -> None:
    """Add Phase 10 authorization columns to databases created before Alembic startup."""

    inspector = inspect(connection)
    if "code_projects" not in inspector.get_table_names():
        return
    columns = {str(column["name"]) for column in inspector.get_columns("code_projects")}
    if "authorization_confirmed" not in columns:
        connection.exec_driver_sql(
            "ALTER TABLE code_projects ADD COLUMN "
            "authorization_confirmed BOOLEAN NOT NULL DEFAULT FALSE"
        )
    if "authorization_notes" not in columns:
        connection.exec_driver_sql(
            "ALTER TABLE code_projects ADD COLUMN authorization_notes TEXT NOT NULL DEFAULT ''"
        )
