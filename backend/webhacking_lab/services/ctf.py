"""Create, update, and track CTF challenges."""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.api.schemas.ctf import (
    CtfChallengeCreate,
    CtfChallengePatch,
    CtfChallengeRead,
)
from webhacking_lab.database.models import CtfChallenge
from webhacking_lab.database.repositories.audit import AuditRepository
from webhacking_lab.database.repositories.ctf import CtfChallengeRepository
from webhacking_lab.domain.enums import AuditEventType, CtfChallengeStatus
from webhacking_lab.domain.exceptions import EntityNotFoundError


class CtfService:
    """Manage the CTF Workspace challenge tracker."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._challenges = CtfChallengeRepository(session)
        self._audit = AuditRepository(session)

    async def create(
        self, data: CtfChallengeCreate, correlation_id: str | None
    ) -> CtfChallengeRead:
        challenge = CtfChallenge(
            name=data.name.strip(),
            event=data.event.strip(),
            category=data.category.strip(),
            difficulty=data.difficulty.strip(),
            points=data.points,
            target_url=data.target_url.strip(),
            status=data.status,
            notes=data.notes,
            flag=data.flag,
            solved_at=datetime.now(UTC) if data.status == CtfChallengeStatus.SOLVED else None,
        )
        await self._challenges.add(challenge)
        await self._audit.record(
            AuditEventType.CTF_CHALLENGE_CREATED,
            resource_type="ctf_challenge",
            resource_id=challenge.id,
            correlation_id=correlation_id,
            details={"event": challenge.event, "status": challenge.status.value},
        )
        await self._session.commit()
        await self._session.refresh(challenge)
        return CtfChallengeRead.model_validate(challenge)

    async def list(self, event: str | None = None) -> list[CtfChallengeRead]:
        challenges = await self._challenges.list(event)
        return [CtfChallengeRead.model_validate(item) for item in challenges]

    async def get(self, challenge_id: UUID) -> CtfChallengeRead:
        challenge = await self._require(challenge_id)
        return CtfChallengeRead.model_validate(challenge)

    async def update(
        self, challenge_id: UUID, data: CtfChallengePatch, correlation_id: str | None
    ) -> CtfChallengeRead:
        challenge = await self._require(challenge_id)
        fields = data.model_dump(exclude_unset=True)
        for key in ("name", "event", "category", "difficulty", "target_url"):
            if key in fields and fields[key] is not None:
                fields[key] = fields[key].strip()
        for key, value in fields.items():
            setattr(challenge, key, value)
        # Keep solved_at consistent with the status transition.
        if "status" in fields:
            if challenge.status == CtfChallengeStatus.SOLVED and challenge.solved_at is None:
                challenge.solved_at = datetime.now(UTC)
            elif challenge.status != CtfChallengeStatus.SOLVED:
                challenge.solved_at = None
        await self._audit.record(
            AuditEventType.CTF_CHALLENGE_UPDATED,
            resource_type="ctf_challenge",
            resource_id=challenge.id,
            correlation_id=correlation_id,
            details={"fields": sorted(fields.keys())},
        )
        await self._session.commit()
        await self._session.refresh(challenge)
        return CtfChallengeRead.model_validate(challenge)

    async def delete(self, challenge_id: UUID, correlation_id: str | None) -> None:
        challenge = await self._require(challenge_id)
        await self._challenges.delete(challenge)
        await self._audit.record(
            AuditEventType.CTF_CHALLENGE_DELETED,
            resource_type="ctf_challenge",
            resource_id=challenge_id,
            correlation_id=correlation_id,
        )
        await self._session.commit()

    async def _require(self, challenge_id: UUID) -> CtfChallenge:
        challenge = await self._challenges.get(challenge_id)
        if challenge is None:
            raise EntityNotFoundError("CTF challenge was not found")
        return challenge
