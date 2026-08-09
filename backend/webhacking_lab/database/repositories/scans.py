"""Persistence operations for passive scanner jobs and inventories."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from webhacking_lab.database.models import (
    ScanEndpoint,
    ScanEvent,
    ScanFinding,
    ScanJob,
    ScanParameter,
    ScanTestCase,
)


class ScanRepository:
    """Store scanner state without exposing queries to routers."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add_job(self, job: ScanJob) -> ScanJob:
        self._session.add(job)
        await self._session.flush()
        return job

    async def get_job(self, scan_id: UUID) -> ScanJob | None:
        job: ScanJob | None = await self._session.scalar(
            select(ScanJob)
            .where(ScanJob.id == scan_id, ScanJob.deleted_at.is_(None))
            .options(
                selectinload(ScanJob.endpoints),
                selectinload(ScanJob.parameters),
                selectinload(ScanJob.findings),
                selectinload(ScanJob.events),
                selectinload(ScanJob.test_cases),
            )
        )
        return job

    async def list_jobs(self, project_id: UUID | None = None) -> list[ScanJob]:
        statement = (
            select(ScanJob)
            .where(ScanJob.deleted_at.is_(None))
            .options(
                selectinload(ScanJob.endpoints),
                selectinload(ScanJob.parameters),
                selectinload(ScanJob.findings),
                selectinload(ScanJob.events),
                selectinload(ScanJob.test_cases),
            )
            .order_by(ScanJob.created_at.desc())
        )
        if project_id is not None:
            statement = statement.where(ScanJob.project_id == project_id)
        result = await self._session.scalars(statement)
        return list(result.unique())

    async def add_endpoint(self, endpoint: ScanEndpoint) -> ScanEndpoint:
        self._session.add(endpoint)
        await self._session.flush()
        return endpoint

    async def list_endpoints(self, scan_id: UUID) -> list[ScanEndpoint]:
        result = await self._session.scalars(
            select(ScanEndpoint)
            .where(ScanEndpoint.scan_id == scan_id)
            .order_by(ScanEndpoint.depth, ScanEndpoint.url, ScanEndpoint.method)
        )
        return list(result)

    async def add_parameter(self, parameter: ScanParameter) -> ScanParameter:
        self._session.add(parameter)
        await self._session.flush()
        return parameter

    async def list_parameters(self, scan_id: UUID) -> list[ScanParameter]:
        result = await self._session.scalars(
            select(ScanParameter)
            .where(ScanParameter.scan_id == scan_id)
            .order_by(ScanParameter.endpoint_url, ScanParameter.location, ScanParameter.name)
        )
        return list(result)

    async def add_finding(self, finding: ScanFinding) -> ScanFinding:
        self._session.add(finding)
        await self._session.flush()
        return finding

    async def list_findings(self, scan_id: UUID) -> list[ScanFinding]:
        result = await self._session.scalars(
            select(ScanFinding)
            .where(ScanFinding.scan_id == scan_id)
            .order_by(ScanFinding.confidence.desc(), ScanFinding.created_at)
        )
        return list(result)

    async def add_event(self, event: ScanEvent) -> ScanEvent:
        self._session.add(event)
        await self._session.flush()
        return event

    async def list_events(self, scan_id: UUID) -> list[ScanEvent]:
        result = await self._session.scalars(
            select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.created_at)
        )
        return list(result)

    async def add_test_case(self, test_case: ScanTestCase) -> ScanTestCase:
        self._session.add(test_case)
        await self._session.flush()
        return test_case

    async def get_test_case(self, test_id: UUID) -> ScanTestCase | None:
        return await self._session.get(ScanTestCase, test_id)

    async def list_test_cases(self, scan_id: UUID) -> list[ScanTestCase]:
        result = await self._session.scalars(
            select(ScanTestCase)
            .where(ScanTestCase.scan_id == scan_id)
            .order_by(ScanTestCase.created_at, ScanTestCase.plugin_id)
        )
        return list(result)
