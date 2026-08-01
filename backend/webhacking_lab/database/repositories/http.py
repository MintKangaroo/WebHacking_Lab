"""Normalized HTTP exchange persistence operations."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from webhacking_lab.database.models import HttpRequest, HttpResponse, RequestRevision


class HttpRepository:
    """Persist redacted requests, revisions, and imported responses."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add_request(self, request: HttpRequest) -> HttpRequest:
        self._session.add(request)
        await self._session.flush()
        return request

    async def add_revision(self, revision: RequestRevision) -> RequestRevision:
        self._session.add(revision)
        await self._session.flush()
        return revision

    async def add_response(self, response: HttpResponse) -> HttpResponse:
        self._session.add(response)
        await self._session.flush()
        return response

    async def get_request(self, request_id: UUID) -> HttpRequest | None:
        request: HttpRequest | None = await self._session.scalar(
            select(HttpRequest)
            .where(HttpRequest.id == request_id, HttpRequest.deleted_at.is_(None))
            .options(
                selectinload(HttpRequest.revisions),
                selectinload(HttpRequest.responses),
            )
        )
        return request

    async def get_response(self, response_id: UUID) -> HttpResponse | None:
        response: HttpResponse | None = await self._session.scalar(
            select(HttpResponse).where(
                HttpResponse.id == response_id,
                HttpResponse.deleted_at.is_(None),
            )
        )
        return response
