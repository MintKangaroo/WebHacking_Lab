"""Project, workspace, and scope configuration endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.api.dependencies import (
    get_db_session,
    get_dns_resolver,
    get_request_settings,
)
from webhacking_lab.api.schemas.resources import (
    ProjectCreate,
    ProjectDetail,
    ProjectPatch,
    ProjectSummary,
    ScopeCheckRequest,
    ScopeCheckResponse,
    ScopeRuleCreate,
    ScopeRuleRead,
    WorkspaceCreate,
    WorkspaceExecutionApproval,
    WorkspaceExecutionDisable,
    WorkspacePatch,
    WorkspaceRead,
)
from webhacking_lab.core.config import Settings
from webhacking_lab.http_client.scope_guard import DnsResolver
from webhacking_lab.services.projects import ProjectService, ScopeService, WorkspaceService

router = APIRouter(tags=["projects"])
Session = Annotated[AsyncSession, Depends(get_db_session)]
ActiveSettings = Annotated[Settings, Depends(get_request_settings)]
ActiveResolver = Annotated[DnsResolver, Depends(get_dns_resolver)]


def correlation_id(request: Request) -> str | None:
    """Read the request identifier assigned by middleware."""

    value: str | None = getattr(request.state, "correlation_id", None)
    return value


@router.post(
    "/projects",
    response_model=ProjectDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Create an authorized analysis project",
)
async def create_project(data: ProjectCreate, request: Request, session: Session) -> ProjectDetail:
    return await ProjectService(session).create(data, correlation_id(request))


@router.get("/projects", response_model=list[ProjectSummary], summary="List active projects")
async def list_projects(session: Session) -> list[ProjectSummary]:
    return await ProjectService(session).list()


@router.get("/projects/{project_id}", response_model=ProjectDetail, summary="Get a project")
async def get_project(project_id: UUID, session: Session) -> ProjectDetail:
    return await ProjectService(session).get(project_id)


@router.patch("/projects/{project_id}", response_model=ProjectDetail, summary="Update a project")
async def update_project(
    project_id: UUID,
    data: ProjectPatch,
    request: Request,
    session: Session,
) -> ProjectDetail:
    return await ProjectService(session).update(project_id, data, correlation_id(request))


@router.delete(
    "/projects/{project_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Soft-delete a project",
)
async def delete_project(project_id: UUID, request: Request, session: Session) -> Response:
    await ProjectService(session).delete(project_id, correlation_id(request))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/projects/{project_id}/scope",
    response_model=ScopeRuleRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register an allowlist rule",
)
async def add_scope_rule(
    project_id: UUID,
    data: ScopeRuleCreate,
    request: Request,
    session: Session,
) -> ScopeRuleRead:
    return await ScopeService(session).add(project_id, data, correlation_id(request))


@router.get(
    "/projects/{project_id}/scope",
    response_model=list[ScopeRuleRead],
    summary="List project allowlist rules",
)
async def list_scope_rules(project_id: UUID, session: Session) -> list[ScopeRuleRead]:
    return await ScopeService(session).list(project_id)


@router.post(
    "/projects/{project_id}/scope/check",
    response_model=ScopeCheckResponse,
    summary="Preview Scope Guard without sending a request",
)
async def check_scope(
    project_id: UUID,
    data: ScopeCheckRequest,
    request: Request,
    session: Session,
    resolver: ActiveResolver,
) -> ScopeCheckResponse:
    return await ScopeService(session, resolver).check(
        project_id,
        data.url,
        correlation_id(request),
    )


@router.post(
    "/workspaces",
    response_model=WorkspaceRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create an analysis-only workspace",
)
async def create_workspace(
    data: WorkspaceCreate,
    request: Request,
    session: Session,
) -> WorkspaceRead:
    return await WorkspaceService(session).create(data, correlation_id(request))


@router.get(
    "/workspaces/{workspace_id}",
    response_model=WorkspaceRead,
    summary="Get a workspace",
)
async def get_workspace(workspace_id: UUID, session: Session) -> WorkspaceRead:
    return await WorkspaceService(session).get(workspace_id)


@router.patch(
    "/workspaces/{workspace_id}",
    response_model=WorkspaceRead,
    summary="Update analysis workspace metadata",
)
async def update_workspace(
    workspace_id: UUID,
    data: WorkspacePatch,
    request: Request,
    session: Session,
) -> WorkspaceRead:
    return await WorkspaceService(session).update(workspace_id, data, correlation_id(request))


@router.post(
    "/workspaces/{workspace_id}/execution/enable",
    response_model=WorkspaceRead,
    summary="Explicitly enable controlled requests for a workspace",
)
async def enable_workspace_execution(
    workspace_id: UUID,
    data: WorkspaceExecutionApproval,
    request: Request,
    session: Session,
    settings: ActiveSettings,
) -> WorkspaceRead:
    return await WorkspaceService(session, settings).enable_execution(
        workspace_id,
        data,
        correlation_id(request),
    )


@router.post(
    "/workspaces/{workspace_id}/execution/disable",
    response_model=WorkspaceRead,
    summary="Disable controlled requests for a workspace",
)
async def disable_workspace_execution(
    workspace_id: UUID,
    data: WorkspaceExecutionDisable,
    request: Request,
    session: Session,
) -> WorkspaceRead:
    return await WorkspaceService(session).disable_execution(
        workspace_id,
        data,
        correlation_id(request),
    )
