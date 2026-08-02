"""FastAPI dependency providers."""

from collections.abc import AsyncIterator

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.core.config import Settings
from webhacking_lab.core.rate_limit import RequestGate
from webhacking_lab.database.session import Database
from webhacking_lab.http_client.client import SingleHopSender
from webhacking_lab.http_client.scope_guard import DnsResolver


def get_request_settings(request: Request) -> Settings:
    """Return settings owned by the running application."""

    settings: Settings = request.app.state.settings
    return settings


def get_request_gate(request: Request) -> RequestGate:
    """Return the application-wide outbound request gate."""

    gate: RequestGate = request.app.state.request_gate
    return gate


def get_http_sender(request: Request) -> SingleHopSender:
    """Return the replaceable DNS-pinned HTTP sender."""

    sender: SingleHopSender = request.app.state.http_sender
    return sender


def get_dns_resolver(request: Request) -> DnsResolver:
    """Return the shared, replaceable DNS resolver used by every scope check."""

    resolver: DnsResolver = request.app.state.dns_resolver
    return resolver


async def get_db_session(request: Request) -> AsyncIterator[AsyncSession]:
    """Yield a transactional database session."""

    database: Database = request.app.state.database
    async for session in database.session():
        yield session
