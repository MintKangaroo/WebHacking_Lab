"""Read-only audit event application service."""

from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.api.schemas.resources import AuditEventRead
from webhacking_lab.database.repositories.audit import AuditRepository


class AuditService:
    """Expose already-redacted audit records to API callers."""

    def __init__(self, session: AsyncSession) -> None:
        self._audit = AuditRepository(session)

    async def list(self, limit: int) -> list[AuditEventRead]:
        events = await self._audit.list(limit)
        return [AuditEventRead.model_validate(event) for event in events]
