"""Cancellable passive URL scan endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.api.dependencies import (
    get_db_session,
    get_dns_resolver,
    get_http_sender,
    get_request_gate,
    get_request_settings,
)
from webhacking_lab.core.config import Settings
from webhacking_lab.core.rate_limit import RequestGate
from webhacking_lab.database.session import Database
from webhacking_lab.http_client.client import SingleHopSender
from webhacking_lab.http_client.scope_guard import DnsResolver
from webhacking_lab.scanner.engine import run_scan_job
from webhacking_lab.scanner.jobs import ScanTaskRegistry
from webhacking_lab.scanner.models import (
    ScanCancelRead,
    ScanEndpointRead,
    ScanEventRead,
    ScanFindingRead,
    ScanJobCreate,
    ScanJobRead,
    ScanParameterRead,
)
from webhacking_lab.services.scans import ScanService

router = APIRouter(tags=["scanner"])
Session = Annotated[AsyncSession, Depends(get_db_session)]
ActiveSettings = Annotated[Settings, Depends(get_request_settings)]
ActiveResolver = Annotated[DnsResolver, Depends(get_dns_resolver)]
ActiveGate = Annotated[RequestGate, Depends(get_request_gate)]
ActiveSender = Annotated[SingleHopSender, Depends(get_http_sender)]


def _correlation_id(request: Request) -> str | None:
    value: str | None = getattr(request.state, "correlation_id", None)
    return value


@router.post(
    "/scans",
    response_model=ScanJobRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start one explicitly approved bounded passive URL scan",
)
async def create_scan(
    data: ScanJobCreate,
    request: Request,
    session: Session,
    settings: ActiveSettings,
    resolver: ActiveResolver,
    gate: ActiveGate,
    sender: ActiveSender,
) -> ScanJobRead:
    result = await ScanService(session, settings, resolver).create(
        data,
        _correlation_id(request),
    )
    database: Database = request.app.state.database
    tasks: ScanTaskRegistry = request.app.state.scan_tasks
    tasks.start(
        result.id,
        run_scan_job(
            database,
            settings,
            gate,
            sender,
            resolver,
            result.id,
            _correlation_id(request),
        ),
    )
    return result


@router.get("/scans", response_model=list[ScanJobRead], summary="List scanner jobs")
async def list_scans(
    session: Session,
    settings: ActiveSettings,
    resolver: ActiveResolver,
    project_id: Annotated[UUID | None, Query()] = None,
) -> list[ScanJobRead]:
    return await ScanService(session, settings, resolver).list_jobs(project_id)


@router.get("/scans/{scan_id}", response_model=ScanJobRead, summary="Get scanner status")
async def get_scan(
    scan_id: UUID,
    session: Session,
    settings: ActiveSettings,
    resolver: ActiveResolver,
) -> ScanJobRead:
    return await ScanService(session, settings, resolver).get(scan_id)


@router.post(
    "/scans/{scan_id}/cancel",
    response_model=ScanCancelRead,
    summary="Request cooperative scanner cancellation",
)
async def cancel_scan(
    scan_id: UUID,
    request: Request,
    session: Session,
    settings: ActiveSettings,
    resolver: ActiveResolver,
) -> ScanCancelRead:
    return await ScanService(session, settings, resolver).cancel(
        scan_id,
        _correlation_id(request),
    )


@router.get(
    "/scans/{scan_id}/events",
    response_model=list[ScanEventRead],
    summary="Get ordered scanner progress events",
)
async def get_scan_events(
    scan_id: UUID,
    session: Session,
    settings: ActiveSettings,
    resolver: ActiveResolver,
) -> list[ScanEventRead]:
    return await ScanService(session, settings, resolver).events(scan_id)


@router.get(
    "/scans/{scan_id}/endpoints",
    response_model=list[ScanEndpointRead],
    summary="Get endpoint inventory",
)
async def get_scan_endpoints(
    scan_id: UUID,
    session: Session,
    settings: ActiveSettings,
    resolver: ActiveResolver,
) -> list[ScanEndpointRead]:
    return await ScanService(session, settings, resolver).endpoints(scan_id)


@router.get(
    "/scans/{scan_id}/parameters",
    response_model=list[ScanParameterRead],
    summary="Get parameter inventory",
)
async def get_scan_parameters(
    scan_id: UUID,
    session: Session,
    settings: ActiveSettings,
    resolver: ActiveResolver,
) -> list[ScanParameterRead]:
    return await ScanService(session, settings, resolver).parameters(scan_id)


@router.get(
    "/scans/{scan_id}/findings",
    response_model=list[ScanFindingRead],
    summary="Get passive scanner candidates",
)
async def get_scan_findings(
    scan_id: UUID,
    session: Session,
    settings: ActiveSettings,
    resolver: ActiveResolver,
) -> list[ScanFindingRead]:
    return await ScanService(session, settings, resolver).findings(scan_id)
