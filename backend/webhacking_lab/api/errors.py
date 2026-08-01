"""Stable API error representation and handlers."""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from webhacking_lab.domain.exceptions import DomainError


class ErrorBody(BaseModel):
    """Client-safe error envelope."""

    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    correlation_id: str


def install_error_handlers(app: FastAPI) -> None:
    """Install the last-resort handler without exposing internals."""

    @app.exception_handler(DomainError)
    async def domain_error_handler(request: Request, exception: DomainError) -> JSONResponse:
        correlation_id = getattr(request.state, "correlation_id", "unavailable")
        body = ErrorBody(
            code=exception.code,
            message=str(exception),
            correlation_id=correlation_id,
        )
        return JSONResponse(status_code=exception.status_code, content=body.model_dump())

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, _exception: Exception) -> JSONResponse:
        correlation_id = getattr(request.state, "correlation_id", "unavailable")
        body = ErrorBody(
            code="internal_error",
            message="The request could not be completed.",
            correlation_id=correlation_id,
        )
        return JSONResponse(status_code=500, content=body.model_dump())
