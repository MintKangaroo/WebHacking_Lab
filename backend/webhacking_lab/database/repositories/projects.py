"""Project, workspace, and scope persistence operations."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from webhacking_lab.database.models import Project, ScopeRule, Workspace


class ProjectRepository:
    """Persist project aggregates without exposing queries to routers."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, project: Project) -> Project:
        self._session.add(project)
        await self._session.flush()
        return project

    async def list(self) -> list[Project]:
        result = await self._session.scalars(
            select(Project)
            .where(Project.deleted_at.is_(None))
            .options(selectinload(Project.workspaces), selectinload(Project.scope_rules))
            .order_by(Project.updated_at.desc())
        )
        return list(result.unique())

    async def get(self, project_id: UUID) -> Project | None:
        project: Project | None = await self._session.scalar(
            select(Project)
            .where(Project.id == project_id, Project.deleted_at.is_(None))
            .options(selectinload(Project.workspaces), selectinload(Project.scope_rules))
        )
        return project


class WorkspaceRepository:
    """Persist workspace records."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, workspace: Workspace) -> Workspace:
        self._session.add(workspace)
        await self._session.flush()
        return workspace

    async def get(self, workspace_id: UUID) -> Workspace | None:
        workspace: Workspace | None = await self._session.scalar(
            select(Workspace).where(
                Workspace.id == workspace_id,
                Workspace.deleted_at.is_(None),
            )
        )
        return workspace


class ScopeRuleRepository:
    """Persist and retrieve scope rules by project."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, rule: ScopeRule) -> ScopeRule:
        self._session.add(rule)
        await self._session.flush()
        return rule

    async def list_for_project(self, project_id: UUID) -> list[ScopeRule]:
        result = await self._session.scalars(
            select(ScopeRule)
            .where(
                ScopeRule.project_id == project_id,
                ScopeRule.deleted_at.is_(None),
            )
            .order_by(ScopeRule.created_at.asc())
        )
        return list(result)
