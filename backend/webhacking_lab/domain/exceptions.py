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


class ExecutionPolicyError(DomainError):
    """Raised when controlled network execution is not explicitly authorized."""

    code = "execution_blocked"
    status_code = 403


class AuthorizationRequiredError(DomainError):
    """Raised when an operation lacks a persisted explicit-authorization record."""

    code = "authorization_required"
    status_code = 403


class RateLimitError(DomainError):
    """Raised when a global or target request limit is exhausted."""

    code = "rate_limited"
    status_code = 429


class UpstreamRequestError(DomainError):
    """Raised when an approved request cannot be completed safely."""

    code = "upstream_request_failed"
    status_code = 502


class ResponseLimitError(DomainError):
    """Raised when an upstream response exceeds its configured byte limit."""

    code = "response_too_large"
    status_code = 413


class UploadValidationError(DomainError):
    """Raised when an untrusted source upload violates its inert-storage policy."""

    code = "invalid_source_upload"
    status_code = 422


class UploadLimitError(DomainError):
    """Raised when an uploaded archive or source tree exceeds a hard ceiling."""

    code = "source_upload_too_large"
    status_code = 413
