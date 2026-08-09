"""Secure source upload and non-executing code inventory endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, Query, Request, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.api.dependencies import get_db_session, get_request_settings
from webhacking_lab.core.config import Settings
from webhacking_lab.services.code_projects import CodeProjectService
from webhacking_lab.static_analysis.models import (
    CodeAnalysisRead,
    CodeFileContentRead,
    CodeFileRead,
    CodeProjectCreate,
    CodeProjectRead,
    CodeUploadRead,
    StaticRoute,
)

router = APIRouter(tags=["code-analysis"])
Session = Annotated[AsyncSession, Depends(get_db_session)]
ActiveSettings = Annotated[Settings, Depends(get_request_settings)]


def _correlation_id(request: Request) -> str | None:
    value: str | None = getattr(request.state, "correlation_id", None)
    return value


@router.post(
    "/code-projects",
    response_model=CodeProjectRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create an inert code-analysis project",
)
async def create_code_project(
    data: CodeProjectCreate,
    request: Request,
    session: Session,
    settings: ActiveSettings,
) -> CodeProjectRead:
    return await CodeProjectService(session, settings).create(data, _correlation_id(request))


@router.get(
    "/code-projects",
    response_model=list[CodeProjectRead],
    summary="List source-analysis projects",
)
async def list_code_projects(
    session: Session,
    settings: ActiveSettings,
    project_id: Annotated[UUID | None, Query()] = None,
) -> list[CodeProjectRead]:
    return await CodeProjectService(session, settings).list_projects(project_id)


@router.post(
    "/code-projects/upload",
    response_model=CodeUploadRead,
    status_code=status.HTTP_201_CREATED,
    summary="Upload bounded source files or one guarded ZIP without execution",
)
async def upload_code_project(
    request: Request,
    session: Session,
    settings: ActiveSettings,
    code_project_id: Annotated[UUID, Form()],
    files: Annotated[list[UploadFile], File(description="Source files or one ZIP archive")],
) -> CodeUploadRead:
    return await CodeProjectService(session, settings).upload(
        code_project_id,
        files,
        _correlation_id(request),
    )


@router.get(
    "/code-projects/{code_project_id}",
    response_model=CodeProjectRead,
    summary="Get a source-analysis project",
)
async def get_code_project(
    code_project_id: UUID,
    session: Session,
    settings: ActiveSettings,
) -> CodeProjectRead:
    return await CodeProjectService(session, settings).get(code_project_id)


@router.get(
    "/code-projects/{code_project_id}/files",
    response_model=list[CodeFileRead],
    summary="List indexed source files without content",
)
async def list_code_files(
    code_project_id: UUID,
    session: Session,
    settings: ActiveSettings,
) -> list[CodeFileRead]:
    return await CodeProjectService(session, settings).files(code_project_id)


@router.get(
    "/code-projects/{code_project_id}/files/{file_id}",
    response_model=CodeFileContentRead,
    summary="Read one size-bounded source file with secrets masked",
)
async def get_code_file(
    code_project_id: UUID,
    file_id: UUID,
    session: Session,
    settings: ActiveSettings,
) -> CodeFileContentRead:
    return await CodeProjectService(session, settings).file_content(code_project_id, file_id)


@router.get(
    "/code-projects/{code_project_id}/routes",
    response_model=list[StaticRoute],
    summary="Get extracted static route inventory",
)
async def list_code_routes(
    code_project_id: UUID,
    session: Session,
    settings: ActiveSettings,
) -> list[StaticRoute]:
    return await CodeProjectService(session, settings).routes(code_project_id)


@router.post(
    "/code-projects/{code_project_id}/analyze",
    response_model=CodeAnalysisRead,
    summary="Analyze uploaded source without executing or installing it",
)
async def analyze_code_project(
    code_project_id: UUID,
    request: Request,
    session: Session,
    settings: ActiveSettings,
) -> CodeAnalysisRead:
    return await CodeProjectService(session, settings).analyze(
        code_project_id,
        _correlation_id(request),
    )


@router.get(
    "/code-projects/{code_project_id}/analysis",
    response_model=CodeAnalysisRead,
    summary="Get the latest source inventory analysis",
)
async def get_code_analysis(
    code_project_id: UUID,
    session: Session,
    settings: ActiveSettings,
) -> CodeAnalysisRead:
    return await CodeProjectService(session, settings).analysis(code_project_id)
