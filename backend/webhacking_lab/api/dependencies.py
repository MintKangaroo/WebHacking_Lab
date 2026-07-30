"""FastAPI dependency providers."""

from collections.abc import AsyncIterator

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.core.config import Settings
from webhacking_lab.database.session import Database


def get_request_settings(request: Request) -> Settings:
    """Return settings owned by the running application."""

    settings: Settings = request.app.state.settings
    return settings


async def get_db_session(request: Request) -> AsyncIterator[AsyncSession]:
    """Yield a transactional database session."""

    database: Database = request.app.state.database
    async for session in database.session():
        yield session
