"""Project, scope, workspace, and HTTP API contracts."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webhacking_lab.domain.enums import AnalysisMode, WorkspaceMode
from webhacking_lab.http_client.models import (
    ImportedExchange,
    NameValue,
    NormalizedRequest,
    NormalizedResponse,
    ScopeDecision,
)


class ApiModel(BaseModel):
    """Strict public API base model."""

    model_config = ConfigDict(extra="forbid", from_attributes=True)


class ProjectCreate(ApiModel):
    """Create a top-level authorized project."""

    name: str = Field(min_length=1, max_length=160, examples=["Local Shop Review"])
    description: str = Field(default="", max_length=4000)
    mode: WorkspaceMode


class ProjectPatch(ApiModel):
    """Patch mutable project fields."""

    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=4000)
    mode: WorkspaceMode | None = None
    version: int = Field(ge=1)


class ProjectSummary(ApiModel):
    """Project list representation."""

    id: UUID
    name: str
    description: str
    mode: WorkspaceMode
    version: int
    workspace_count: int
    scope_rule_count: int
    created_at: datetime
    updated_at: datetime


class WorkspaceCreate(ApiModel):
    """Create an analysis workspace."""

    project_id: UUID
    name: str = Field(min_length=1, max_length=160)
    mode: WorkspaceMode | None = None
    analysis_mode: AnalysisMode = AnalysisMode.MANUAL_HTTP
    request_budget: int = Field(default=100, ge=1, le=1000)


class WorkspacePatch(ApiModel):
    """Patch workspace metadata; execution cannot be enabled in Phase 2."""

    name: str | None = Field(default=None, min_length=1, max_length=160)
    analysis_mode: AnalysisMode | None = None
    request_budget: int | None = Field(default=None, ge=1, le=1000)
    version: int = Field(ge=1)


class WorkspaceRead(ApiModel):
    """Workspace representation with safety budget."""

    id: UUID
    project_id: UUID
    name: str
    mode: WorkspaceMode
    analysis_mode: AnalysisMode
    network_execution_enabled: bool
    request_budget: int
    requests_used: int
    version: int
    created_at: datetime
    updated_at: datetime


class ScopeRuleCreate(ApiModel):
    """Register a bounded URL allowlist rule."""

    scheme: str = Field(pattern="^(http|https)$")
    hostname: str = Field(min_length=1, max_length=253)
    port: int | None = Field(default=None, ge=1, le=65535)
    path_prefix: str = Field(default="/", max_length=1024)
    allow_subdomains: bool = False
    max_requests_per_minute: int = Field(default=10, ge=1, le=120)
    max_concurrency: int = Field(default=2, ge=1, le=5)
    authorization_confirmed: bool = False
    authorization_notes: str = Field(default="", max_length=2000)

    @field_validator("path_prefix")
    @classmethod
    def require_absolute_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("path_prefix must start with /")
        return value


class ScopeRuleRead(ApiModel):
    """Persisted scope rule."""

    id: UUID
    project_id: UUID
    scheme: str
    hostname: str
    port: int | None
    path_prefix: str
    allow_subdomains: bool
    max_requests_per_minute: int
    max_concurrency: int
    authorization_confirmed: bool
    authorization_notes: str
    created_at: datetime


class ScopeCheckRequest(ApiModel):
    """Preview Scope Guard policy for a URL without sending a request."""

    url: str = Field(min_length=1, max_length=8192, examples=["http://127.0.0.1:5000/"])


class ProjectDetail(ProjectSummary):
    """Project with nested workspace and scope configuration."""

    workspaces: list[WorkspaceRead]
    scope_rules: list[ScopeRuleRead]


class HttpRequestCreate(ApiModel):
    """Create a normalized request from structured fields."""

    workspace_id: UUID
    method: str = Field(default="GET", min_length=1, max_length=16)
    url: str = Field(min_length=1, max_length=8192)
    query: list[NameValue] = Field(default_factory=list)
    headers: list[NameValue] = Field(default_factory=list)
    cookies: list[NameValue] = Field(default_factory=list)
    body: str = ""


class CurlImportRequest(ApiModel):
    """Import cURL text as data; the command is never executed."""

    command: str = Field(min_length=1, examples=["curl 'http://127.0.0.1:5000/search?q=test'"])
    workspace_id: UUID | None = None
    persist: bool = False


class HarImportRequest(ApiModel):
    """Import a HAR JSON document as text for accurate size enforcement."""

    content: str = Field(min_length=1)
    workspace_id: UUID | None = None
    persist: bool = False


class ImportResult(ApiModel):
    """Preview or persisted HTTP import result."""

    exchanges: list[ImportedExchange]
    request_ids: list[UUID] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class RequestRevisionRead(ApiModel):
    """Request revision metadata."""

    id: UUID
    revision_number: int
    change_summary: str
    created_at: datetime


class HttpResponseRead(ApiModel):
    """Stored imported response."""

    id: UUID
    request_id: UUID
    status_code: int
    normalized: NormalizedResponse
    body_size: int
    elapsed_ms: float | None
    created_at: datetime


class HttpRequestRead(ApiModel):
    """Stored redacted request and related evidence."""

    id: UUID
    workspace_id: UUID
    method: str
    url: str
    normalized: NormalizedRequest
    raw_http_redacted: str
    body_size: int
    source: str
    version: int
    revisions: list[RequestRevisionRead] = Field(default_factory=list)
    responses: list[HttpResponseRead] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class AuditEventRead(ApiModel):
    """Redacted append-only audit event."""

    id: UUID
    event_type: str
    actor: str
    project_id: UUID | None
    workspace_id: UUID | None
    resource_type: str
    resource_id: UUID | None
    correlation_id: str | None
    details: dict[str, Any]
    created_at: datetime


ScopeCheckResponse = ScopeDecision
