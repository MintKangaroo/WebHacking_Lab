"""Persistence for tracked CTF challenges."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.database.models import CtfChallenge


class CtfChallengeRepository:
    """CRUD access for CTF challenges in the caller's transaction."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, challenge: CtfChallenge) -> CtfChallenge:
        self._session.add(challenge)
        await self._session.flush()
        return challenge

    async def get(self, challenge_id: UUID) -> CtfChallenge | None:
        return await self._session.get(CtfChallenge, challenge_id)

    async def list(self, event: str | None = None) -> list[CtfChallenge]:
        statement = select(CtfChallenge)
        if event is not None:
            statement = statement.where(CtfChallenge.event == event)
        statement = statement.order_by(CtfChallenge.event.asc(), CtfChallenge.created_at.asc())
        return list(await self._session.scalars(statement))

    async def delete(self, challenge: CtfChallenge) -> None:
        await self._session.delete(challenge)
        await self._session.flush()
