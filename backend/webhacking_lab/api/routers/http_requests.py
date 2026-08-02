"""HTTP request import and persistence endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.api.dependencies import (
    get_db_session,
    get_dns_resolver,
    get_http_sender,
    get_request_gate,
    get_request_settings,
)
from webhacking_lab.api.schemas.resources import (
    CurlImportRequest,
    HarImportRequest,
    HttpRequestCreate,
    HttpRequestRead,
    HttpResponseRead,
    ImportResult,
    RequestExecutionApproval,
    RequestExecutionPreview,
    RequestExecutionResult,
)
from webhacking_lab.core.config import Settings
from webhacking_lab.core.rate_limit import RequestGate
from webhacking_lab.http_client.client import SingleHopSender
from webhacking_lab.http_client.scope_guard import DnsResolver, ScopeGuard
from webhacking_lab.services.http_requests import HttpRequestService
from webhacking_lab.services.request_execution import RequestExecutionService

router = APIRouter(tags=["http-data"])
Session = Annotated[AsyncSession, Depends(get_db_session)]
ActiveSettings = Annotated[Settings, Depends(get_request_settings)]
ActiveGate = Annotated[RequestGate, Depends(get_request_gate)]
ActiveSender = Annotated[SingleHopSender, Depends(get_http_sender)]
ActiveResolver = Annotated[DnsResolver, Depends(get_dns_resolver)]


def correlation_id(request: Request) -> str | None:
    value: str | None = getattr(request.state, "correlation_id", None)
    return value


@router.post(
    "/requests/import/curl",
    response_model=ImportResult,
    summary="Parse cURL text without executing it",
)
async def import_curl_request(
    data: CurlImportRequest,
    request: Request,
    session: Session,
    settings: ActiveSettings,
) -> ImportResult:
    return await HttpRequestService(session, settings).import_curl(
        data.command,
        data.workspace_id,
        data.persist,
        correlation_id(request),
    )


@router.post(
    "/requests/import/har",
    response_model=ImportResult,
    summary="Parse a bounded HAR document without replaying it",
)
async def import_har_request(
    data: HarImportRequest,
    request: Request,
    session: Session,
    settings: ActiveSettings,
) -> ImportResult:
    return await HttpRequestService(session, settings).import_har(
        data.content,
        data.workspace_id,
        data.persist,
        correlation_id(request),
    )


@router.post(
    "/requests",
    response_model=HttpRequestRead,
    status_code=status.HTTP_201_CREATED,
    summary="Store a normalized, redacted request",
)
async def create_http_request(
    data: HttpRequestCreate,
    request: Request,
    session: Session,
    settings: ActiveSettings,
) -> HttpRequestRead:
    return await HttpRequestService(session, settings).create(data, correlation_id(request))


@router.get("/requests/{request_id}", response_model=HttpRequestRead, summary="Get a request")
async def get_http_request(
    request_id: UUID,
    session: Session,
    settings: ActiveSettings,
) -> HttpRequestRead:
    return await HttpRequestService(session, settings).get(request_id)


@router.post(
    "/requests/{request_id}/clone",
    response_model=HttpRequestRead,
    status_code=status.HTTP_201_CREATED,
    summary="Clone a stored request without sending it",
)
async def clone_http_request(
    request_id: UUID,
    request: Request,
    session: Session,
    settings: ActiveSettings,
) -> HttpRequestRead:
    return await HttpRequestService(session, settings).clone(
        request_id,
        correlation_id(request),
    )


@router.get(
    "/responses/{response_id}",
    response_model=HttpResponseRead,
    summary="Get an imported response",
)
async def get_http_response(
    response_id: UUID,
    session: Session,
    settings: ActiveSettings,
) -> HttpResponseRead:
    return await HttpRequestService(session, settings).get_response(response_id)


@router.post(
    "/requests/{request_id}/execute/preview",
    response_model=RequestExecutionPreview,
    summary="Preview an exact controlled request without sending it",
)
async def preview_http_request_execution(
    request_id: UUID,
    request: Request,
    session: Session,
    settings: ActiveSettings,
    gate: ActiveGate,
    sender: ActiveSender,
    resolver: ActiveResolver,
) -> RequestExecutionPreview:
    return await RequestExecutionService(
        session, settings, gate, sender, ScopeGuard(resolver)
    ).preview(
        request_id,
        correlation_id(request),
    )


@router.post(
    "/requests/{request_id}/execute",
    response_model=RequestExecutionResult,
    status_code=status.HTTP_201_CREATED,
    summary="Send one approved read-only request chain",
)
async def execute_http_request(
    request_id: UUID,
    data: RequestExecutionApproval,
    request: Request,
    session: Session,
    settings: ActiveSettings,
    gate: ActiveGate,
    sender: ActiveSender,
    resolver: ActiveResolver,
) -> RequestExecutionResult:
    return await RequestExecutionService(
        session, settings, gate, sender, ScopeGuard(resolver)
    ).execute(
        request_id,
        data,
        correlation_id(request),
    )
