"""Transport-independent normalized HTTP and scope models."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    """Reject fields outside an explicit security contract."""

    model_config = ConfigDict(extra="forbid")


class NameValue(StrictModel):
    """One multimap entry, preserving order and duplicates."""

    name: str = Field(min_length=1, max_length=1024)
    value: str = Field(max_length=2_000_000)
    redacted: bool = False


class RedirectHop(StrictModel):
    """One normalized redirect response."""

    status_code: int = Field(ge=100, le=599)
    url: str
    location: str | None = None


class NormalizedRequest(StrictModel):
    """Canonical, redacted HTTP request representation."""

    method: str = Field(min_length=1, max_length=16)
    scheme: Literal["http", "https"]
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    path: str = Field(min_length=1, max_length=8192)
    query: list[NameValue] = Field(default_factory=list)
    headers: list[NameValue] = Field(default_factory=list)
    cookies: list[NameValue] = Field(default_factory=list)
    body: str = ""
    content_type: str | None = None
    character_encoding: str = "utf-8"

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        """Normalize method casing and reject non-token characters."""

        normalized = value.upper()
        if not normalized.replace("-", "").isalpha():
            raise ValueError("HTTP method contains invalid characters")
        return normalized

    @property
    def url(self) -> str:
        """Build a redacted absolute URL while retaining duplicate query keys."""

        from urllib.parse import urlencode

        default_port = 80 if self.scheme == "http" else 443
        display_host = f"[{self.host}]" if ":" in self.host else self.host
        authority = display_host if self.port == default_port else f"{display_host}:{self.port}"
        query_string = urlencode([(item.name, item.value) for item in self.query])
        return f"{self.scheme}://{authority}{self.path}" + (
            f"?{query_string}" if query_string else ""
        )


class NormalizedResponse(StrictModel):
    """Canonical, redacted imported or executed response representation."""

    status_code: int = Field(ge=100, le=599)
    reason: str = ""
    headers: list[NameValue] = Field(default_factory=list)
    cookies: list[NameValue] = Field(default_factory=list)
    body: str = ""
    content_type: str | None = None
    character_encoding: str = "utf-8"
    elapsed_ms: float | None = Field(default=None, ge=0)
    redirect_history: list[RedirectHop] = Field(default_factory=list)
    body_hash: str = ""
    normalized_body_hash: str = ""


class ImportedExchange(StrictModel):
    """A normalized request plus an optional HAR response."""

    request: NormalizedRequest
    response: NormalizedResponse | None = None


class ScopeRuleSpec(StrictModel):
    """Scope fields consumed by the independent guard."""

    id: UUID | None = None
    scheme: Literal["http", "https"]
    hostname: str
    port: int | None = Field(default=None, ge=1, le=65535)
    path_prefix: str = "/"
    allow_subdomains: bool = False
    max_requests_per_minute: int = Field(default=10, ge=1, le=120)
    max_concurrency: int = Field(default=2, ge=1, le=5)


class ScopeDecision(StrictModel):
    """Explainable decision returned before any future request execution."""

    allowed: bool
    code: str
    reason: str
    normalized_url: str | None = None
    hostname: str | None = None
    resolved_ips: list[str] = Field(default_factory=list)
    matched_rule_id: UUID | None = None
