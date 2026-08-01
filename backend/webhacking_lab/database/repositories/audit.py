"""Append-only audit persistence."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.core.redaction import redact_mapping
from webhacking_lab.database.models import AuditEvent
from webhacking_lab.domain.enums import AuditEventType


class AuditRepository:
    """Append redacted audit events in the caller's transaction."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def record(
        self,
        event_type: AuditEventType,
        *,
        resource_type: str,
        resource_id: UUID | None,
        project_id: UUID | None = None,
        workspace_id: UUID | None = None,
        correlation_id: str | None = None,
        details: dict[str, object] | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_type=event_type,
            resource_type=resource_type,
            resource_id=resource_id,
            project_id=project_id,
            workspace_id=workspace_id,
            correlation_id=correlation_id,
            details=redact_mapping(details or {}),
        )
        self._session.add(event)
        await self._session.flush()
        return event

    async def list(self, limit: int = 100) -> list[AuditEvent]:
        result = await self._session.scalars(
            select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)
        )
        return list(result)
