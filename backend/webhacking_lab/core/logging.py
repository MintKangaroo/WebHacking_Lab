"""Structured JSON logging and request context."""

import logging
import sys
from collections.abc import Mapping, MutableMapping
from contextvars import ContextVar, Token
from typing import Any

import structlog

correlation_id_context: ContextVar[str | None] = ContextVar("correlation_id", default=None)


def add_correlation_id(
    _logger: Any,
    _method_name: str,
    event_dict: MutableMapping[str, Any],
) -> Mapping[str, Any]:
    """Attach the active request correlation identifier to a log event."""

    correlation_id = correlation_id_context.get()
    if correlation_id:
        event_dict["correlation_id"] = correlation_id
    return event_dict


def configure_logging(log_level: str) -> None:
    """Configure standard-library and structlog output."""

    level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level, force=True)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            add_correlation_id,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def bind_correlation_id(value: str) -> Token[str | None]:
    """Bind a correlation identifier and return its reset token."""

    return correlation_id_context.set(value)


def reset_correlation_id(token: Token[str | None]) -> None:
    """Restore the prior request context."""

    correlation_id_context.reset(token)
