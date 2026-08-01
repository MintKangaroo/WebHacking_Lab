"""HTTP normalization, import, persistence, and clone services."""

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.api.schemas.resources import (
    HttpRequestCreate,
    HttpRequestRead,
    HttpResponseRead,
    ImportResult,
    RequestRevisionRead,
)
from webhacking_lab.core.config import Settings
from webhacking_lab.database.models import HttpRequest, HttpResponse, RequestRevision
from webhacking_lab.database.repositories.audit import AuditRepository
from webhacking_lab.database.repositories.http import HttpRepository
from webhacking_lab.database.repositories.projects import WorkspaceRepository
from webhacking_lab.domain.enums import AuditEventType
from webhacking_lab.domain.exceptions import EntityNotFoundError, ImportFormatError
from webhacking_lab.http_client.models import (
    ImportedExchange,
    NormalizedRequest,
    NormalizedResponse,
)
from webhacking_lab.http_client.request_normalizer import normalize_request, render_raw_request
from webhacking_lab.services.http_import import import_curl, import_har


def _response_read(response: HttpResponse) -> HttpResponseRead:
    return HttpResponseRead(
        id=response.id,
        request_id=response.request_id,
        status_code=response.status_code,
        normalized=NormalizedResponse.model_validate(response.normalized_json),
        body_size=response.body_size,
        elapsed_ms=response.elapsed_ms,
        created_at=response.created_at,
    )


def _request_read(request: HttpRequest) -> HttpRequestRead:
    return HttpRequestRead(
        id=request.id,
        workspace_id=request.workspace_id,
        method=request.method,
        url=request.url,
        normalized=NormalizedRequest.model_validate(request.normalized_json),
        raw_http_redacted=request.raw_http_redacted,
        body_size=request.body_size,
        source=request.source,
        version=request.version,
        revisions=[
            RequestRevisionRead(
                id=item.id,
                revision_number=item.revision_number,
                change_summary=item.change_summary,
                created_at=item.created_at,
            )
            for item in sorted(request.revisions, key=lambda revision: revision.revision_number)
        ],
        responses=[_response_read(item) for item in request.responses],
        created_at=request.created_at,
        updated_at=request.updated_at,
    )


class HttpRequestService:
    """Operate only on redacted HTTP data; no method sends a request."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._http = HttpRepository(session)
        self._workspaces = WorkspaceRepository(session)
        self._audit = AuditRepository(session)
        self._settings = settings

    async def _persist_exchange(
        self,
        workspace_id: UUID,
        exchange: ImportedExchange,
        *,
        source: str,
        correlation_id: str | None,
        event_type: AuditEventType,
    ) -> HttpRequest:
        workspace = await self._workspaces.get(workspace_id)
        if workspace is None:
            raise EntityNotFoundError("Workspace was not found")
        normalized = exchange.request
        request = await self._http.add_request(
            HttpRequest(
                workspace_id=workspace_id,
                method=normalized.method,
                url=normalized.url,
                normalized_json=normalized.model_dump(mode="json"),
                raw_http_redacted=render_raw_request(normalized),
                body_size=len(normalized.body.encode("utf-8")),
                source=source,
            )
        )
        await self._http.add_revision(
            RequestRevision(
                request_id=request.id,
                revision_number=1,
                normalized_json=normalized.model_dump(mode="json"),
            )
        )
        if exchange.response is not None:
            response = exchange.response
            await self._http.add_response(
                HttpResponse(
                    request_id=request.id,
                    status_code=response.status_code,
                    normalized_json=response.model_dump(mode="json"),
                    body_size=len(response.body.encode("utf-8")),
                    elapsed_ms=response.elapsed_ms,
                )
            )
        await self._audit.record(
            event_type,
            resource_type="http_request",
            resource_id=request.id,
            project_id=workspace.project_id,
            workspace_id=workspace.id,
            correlation_id=correlation_id,
            details={"method": normalized.method, "host": normalized.host, "source": source},
        )
        return request

    async def create(
        self,
        data: HttpRequestCreate,
        correlation_id: str | None,
    ) -> HttpRequestRead:
        normalized = normalize_request(
            method=data.method,
            url=data.url,
            headers=[(item.name, item.value) for item in data.headers],
            cookies=[(item.name, item.value) for item in data.cookies],
            body=data.body,
            query=[(item.name, item.value) for item in data.query] or None,
            max_body_bytes=self._settings.max_request_bytes,
        )
        request = await self._persist_exchange(
            data.workspace_id,
            ImportedExchange(request=normalized),
            source="manual",
            correlation_id=correlation_id,
            event_type=AuditEventType.REQUEST_CREATED,
        )
        loaded = await self._http.get_request(request.id)
        if loaded is None:
            raise EntityNotFoundError("Created request could not be reloaded")
        return _request_read(loaded)

    async def import_curl(
        self,
        command: str,
        workspace_id: UUID | None,
        persist: bool,
        correlation_id: str | None,
    ) -> ImportResult:
        normalized = import_curl(command, max_body_bytes=self._settings.max_request_bytes)
        exchange = ImportedExchange(request=normalized)
        request_ids: list[UUID] = []
        if persist:
            if workspace_id is None:
                raise ImportFormatError("workspace_id is required when persist is true")
            request = await self._persist_exchange(
                workspace_id,
                exchange,
                source="curl",
                correlation_id=correlation_id,
                event_type=AuditEventType.REQUEST_IMPORTED,
            )
            request_ids.append(request.id)
        return ImportResult(exchanges=[exchange], request_ids=request_ids)

    async def import_har(
        self,
        content: str,
        workspace_id: UUID | None,
        persist: bool,
        correlation_id: str | None,
    ) -> ImportResult:
        exchanges = import_har(
            content,
            max_har_bytes=self._settings.max_har_bytes,
            max_entries=self._settings.max_har_entries,
            max_request_bytes=self._settings.max_request_bytes,
            max_response_bytes=self._settings.max_response_bytes,
        )
        request_ids: list[UUID] = []
        if persist:
            if workspace_id is None:
                raise ImportFormatError("workspace_id is required when persist is true")
            for exchange in exchanges:
                request = await self._persist_exchange(
                    workspace_id,
                    exchange,
                    source="har",
                    correlation_id=correlation_id,
                    event_type=AuditEventType.REQUEST_IMPORTED,
                )
                request_ids.append(request.id)
        return ImportResult(exchanges=exchanges, request_ids=request_ids)

    async def get(self, request_id: UUID) -> HttpRequestRead:
        request = await self._http.get_request(request_id)
        if request is None:
            raise EntityNotFoundError("HTTP request was not found")
        return _request_read(request)

    async def clone(self, request_id: UUID, correlation_id: str | None) -> HttpRequestRead:
        original = await self._http.get_request(request_id)
        if original is None:
            raise EntityNotFoundError("HTTP request was not found")
        normalized = NormalizedRequest.model_validate(original.normalized_json)
        clone = await self._persist_exchange(
            original.workspace_id,
            ImportedExchange(request=normalized),
            source="clone",
            correlation_id=correlation_id,
            event_type=AuditEventType.REQUEST_CLONED,
        )
        loaded = await self._http.get_request(clone.id)
        if loaded is None:
            raise EntityNotFoundError("Cloned request could not be reloaded")
        return _request_read(loaded)

    async def get_response(self, response_id: UUID) -> HttpResponseRead:
        response = await self._http.get_response(response_id)
        if response is None:
            raise EntityNotFoundError("HTTP response was not found")
        return _response_read(response)
