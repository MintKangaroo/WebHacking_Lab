"""FastAPI application factory."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from time import perf_counter
from uuid import uuid4

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import RequestResponseEndpoint

from webhacking_lab import __version__
from webhacking_lab.api.errors import install_error_handlers
from webhacking_lab.api.routers.system import router as system_router
from webhacking_lab.core.config import Settings, get_settings
from webhacking_lab.core.logging import (
    bind_correlation_id,
    configure_logging,
    reset_correlation_id,
)
from webhacking_lab.database.session import Database, ensure_sqlite_directory


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build a fully configured application for production or tests."""

    active_settings = settings or get_settings()
    configure_logging(active_settings.log_level)
    logger = structlog.get_logger(__name__)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        ensure_sqlite_directory(active_settings)
        database = Database(active_settings.database_url)
        application.state.database = database
        await database.initialize()
        logger.info(
            "application_started",
            environment=active_settings.environment,
            analysis_only=active_settings.analysis_only,
            network_execution_enabled=active_settings.network_execution_enabled,
        )
        try:
            yield
        finally:
            await database.close()
            logger.info("application_stopped")

    application = FastAPI(
        title=active_settings.app_name,
        version=__version__,
        description=(
            "Safety-first analysis API for authorized CTF, local lab, and pentest workflows. "
            "Network execution is disabled by default."
        ),
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    application.state.settings = active_settings
    application.add_middleware(
        CORSMiddleware,
        allow_origins=active_settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Accept", "Content-Type", "X-Correlation-ID"],
        expose_headers=["X-Correlation-ID"],
    )

    @application.middleware("http")
    async def request_context(
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        correlation_id = request.headers.get("X-Correlation-ID", str(uuid4()))
        request.state.correlation_id = correlation_id
        token = bind_correlation_id(correlation_id)
        started = perf_counter()
        try:
            response = await call_next(request)
            response.headers["X-Correlation-ID"] = correlation_id
            logger.info(
                "request_completed",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                elapsed_ms=round((perf_counter() - started) * 1000, 2),
            )
            return response
        finally:
            reset_correlation_id(token)

    application.include_router(system_router, prefix="/api")
    install_error_handlers(application)
    return application


app = create_app()
