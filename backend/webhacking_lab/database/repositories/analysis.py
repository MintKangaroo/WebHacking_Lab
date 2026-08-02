"""Passive analysis persistence operations."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.database.models import AnalysisRun


class AnalysisRepository:
    """Persist immutable analyzer output snapshots."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, run: AnalysisRun) -> AnalysisRun:
        self._session.add(run)
        await self._session.flush()
        return run

    async def get(self, analysis_id: UUID) -> AnalysisRun | None:
        run: AnalysisRun | None = await self._session.scalar(
            select(AnalysisRun).where(
                AnalysisRun.id == analysis_id,
                AnalysisRun.deleted_at.is_(None),
            )
        )
        return run
