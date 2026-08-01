"""Read-only audit event endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.api.dependencies import get_db_session
from webhacking_lab.api.schemas.resources import AuditEventRead
from webhacking_lab.services.audit import AuditService

router = APIRouter(tags=["audit"])
Session = Annotated[AsyncSession, Depends(get_db_session)]


@router.get("/audit-events", response_model=list[AuditEventRead], summary="List audit events")
async def list_audit_events(
    session: Session,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[AuditEventRead]:
    return await AuditService(session).list(limit)
