"""Passive analysis and response diff endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.analyzers.models import AnalysisFlow
from webhacking_lab.api.dependencies import get_db_session
from webhacking_lab.api.schemas.resources import (
    AnalysisRunCreate,
    AnalysisRunRead,
    DiffCreate,
    DiffRead,
)
from webhacking_lab.services.analysis import AnalysisService, DiffService

router = APIRouter(tags=["analysis"])
Session = Annotated[AsyncSession, Depends(get_db_session)]


def correlation_id(request: Request) -> str | None:
    """Return the current correlation identifier."""

    value: str | None = getattr(request.state, "correlation_id", None)
    return value


@router.post("/diff", response_model=DiffRead, summary="Compare two redacted responses")
async def compare_responses(data: DiffCreate, session: Session) -> DiffRead:
    return await DiffService(session).compare(data)


@router.post(
    "/analysis",
    response_model=AnalysisRunRead,
    status_code=status.HTTP_201_CREATED,
    summary="Run six passive analyzers",
)
async def run_analysis(
    data: AnalysisRunCreate,
    request: Request,
    session: Session,
) -> AnalysisRunRead:
    return await AnalysisService(session).run(data, correlation_id(request))


@router.get(
    "/analysis/{analysis_id}",
    response_model=AnalysisRunRead,
    summary="Get a passive analysis run",
)
async def get_analysis(analysis_id: UUID, session: Session) -> AnalysisRunRead:
    return await AnalysisService(session).get(analysis_id)


@router.get(
    "/analysis/{analysis_id}/flow",
    response_model=AnalysisFlow,
    summary="Get an analysis workflow graph",
)
async def get_analysis_flow(analysis_id: UUID, session: Session) -> AnalysisFlow:
    return await AnalysisService(session).get_flow(analysis_id)
