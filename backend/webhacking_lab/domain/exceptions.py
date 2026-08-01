"""Application exceptions translated by the API layer."""


class DomainError(Exception):
    """Base class for expected application errors."""

    code = "domain_error"
    status_code = 400


class EntityNotFoundError(DomainError):
    """Raised when a requested entity does not exist."""

    code = "not_found"
    status_code = 404


class ConflictError(DomainError):
    """Raised when a uniqueness or state invariant would be violated."""

    code = "conflict"
    status_code = 409


class ImportFormatError(DomainError):
    """Raised when an HTTP import is malformed or unsupported."""

    code = "invalid_import"
    status_code = 422


class ScopeValidationError(DomainError):
    """Raised when a scope rule cannot be registered safely."""

    code = "invalid_scope"
    status_code = 422
