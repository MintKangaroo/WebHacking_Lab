"""Persistence operations for inert uploaded source inventories."""

from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from webhacking_lab.database.models import CodeFile, CodeProject, StaticRouteRecord


class CodeProjectRepository:
    """Keep static-analysis queries out of API routers and filesystem services."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, project: CodeProject) -> CodeProject:
        self._session.add(project)
        await self._session.flush()
        return project

    async def get(self, code_project_id: UUID) -> CodeProject | None:
        project: CodeProject | None = await self._session.scalar(
            select(CodeProject)
            .where(CodeProject.id == code_project_id, CodeProject.deleted_at.is_(None))
            .options(
                selectinload(CodeProject.files),
                selectinload(CodeProject.routes),
            )
        )
        return project

    async def list_projects(self, project_id: UUID | None = None) -> list[CodeProject]:
        statement = (
            select(CodeProject)
            .where(CodeProject.deleted_at.is_(None))
            .options(selectinload(CodeProject.files), selectinload(CodeProject.routes))
            .order_by(CodeProject.updated_at.desc())
        )
        if project_id is not None:
            statement = statement.where(CodeProject.project_id == project_id)
        result = await self._session.scalars(statement)
        return list(result.unique())

    async def add_file(self, file: CodeFile) -> CodeFile:
        self._session.add(file)
        await self._session.flush()
        return file

    async def get_file(self, file_id: UUID) -> CodeFile | None:
        return await self._session.get(CodeFile, file_id)

    async def list_files(self, code_project_id: UUID) -> list[CodeFile]:
        result = await self._session.scalars(
            select(CodeFile)
            .where(CodeFile.code_project_id == code_project_id)
            .order_by(CodeFile.relative_path)
        )
        return list(result)

    async def replace_routes(
        self,
        code_project_id: UUID,
        routes: list[StaticRouteRecord],
    ) -> None:
        await self._session.execute(
            delete(StaticRouteRecord).where(StaticRouteRecord.code_project_id == code_project_id)
        )
        self._session.add_all(routes)
        await self._session.flush()

    async def list_routes(self, code_project_id: UUID) -> list[StaticRouteRecord]:
        result = await self._session.scalars(
            select(StaticRouteRecord)
            .where(StaticRouteRecord.code_project_id == code_project_id)
            .order_by(StaticRouteRecord.path, StaticRouteRecord.line_start)
        )
        return list(result)
