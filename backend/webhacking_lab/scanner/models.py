"""Typed scanner policy, inventory, and API models."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from webhacking_lab.domain.enums import ScannerProfile, ScanStatus


class ScannerModel(BaseModel):
    """Strict scanner model base."""

    model_config = ConfigDict(extra="forbid", from_attributes=True)


class CrawlPolicy(ScannerModel):
    """Hard ceilings applied before every passive crawl request."""

    max_depth: int = Field(default=3, ge=0, le=5)
    max_pages: int = Field(default=100, ge=1, le=100)
    max_requests: int = Field(default=300, ge=1, le=300)
    max_response_bytes: int = Field(default=2_000_000, ge=1024, le=2_000_000)
    requests_per_second: float = Field(default=1.0, ge=1 / 60, le=5.0)
    concurrency: int = Field(default=2, ge=1, le=2)
    include_subdomains: bool = False
    respect_logout_routes: bool = True
    execute_javascript: bool = False

    @model_validator(mode="after")
    def require_usable_request_budget(self) -> "CrawlPolicy":
        if self.max_requests < self.max_pages:
            raise ValueError("max_requests must be greater than or equal to max_pages")
        return self


class ScanJobCreate(ScannerModel):
    """Explicitly authorize one bounded passive scan plan."""

    project_id: UUID
    workspace_id: UUID
    target: str = Field(min_length=1, max_length=8192)
    profile: ScannerProfile = ScannerProfile.PASSIVE
    crawl_policy: CrawlPolicy = Field(default_factory=CrawlPolicy)
    authorization_confirmed: Literal[True]
    confirmation_phrase: Literal["START PASSIVE SCAN"]
    expected_use: str = Field(min_length=10, max_length=1000)


class DiscoveredEndpoint(ScannerModel):
    """One normalized endpoint candidate from passive content parsing."""

    url: str
    method: str = "GET"
    source: str
    crawlable: bool = True


class DiscoveredParameter(ScannerModel):
    """One source-aware input candidate."""

    endpoint_url: str
    name: str
    location: Literal["query", "path", "form", "json", "header", "cookie", "multipart"]
    sample_value: str = ""
    source: str


class DocumentDiscovery(ScannerModel):
    """Bounded extraction output from one response document."""

    endpoints: list[DiscoveredEndpoint] = Field(default_factory=list)
    parameters: list[DiscoveredParameter] = Field(default_factory=list)
    title: str | None = None


class TechnologyFingerprint(ScannerModel):
    """Explainable, non-assertive technology signal."""

    name: str
    evidence: str
    confidence: float = Field(ge=0, le=1)


class ScanJobRead(ScannerModel):
    """Persisted scan status and inventory counters."""

    id: UUID
    project_id: UUID
    workspace_id: UUID
    profile: ScannerProfile
    target: str
    status: ScanStatus
    current_stage: str
    progress: float
    request_budget: int
    requests_used: int
    endpoints_count: int
    parameters_count: int
    findings_count: int
    cancellation_requested: bool
    crawl_policy: CrawlPolicy
    fingerprints: list[TechnologyFingerprint]
    error_message: str | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ScanEndpointRead(ScannerModel):
    """Runtime endpoint inventory record."""

    id: UUID
    scan_id: UUID
    url: str
    method: str
    source: str
    depth: int
    fetched: bool
    status_code: int | None
    content_type: str | None
    title: str | None
    http_request_id: UUID | None
    http_response_id: UUID | None
    created_at: datetime


class ScanParameterRead(ScannerModel):
    """Runtime parameter inventory record."""

    id: UUID
    scan_id: UUID
    endpoint_url: str
    name: str
    location: str
    sample_value: str
    source: str
    created_at: datetime


class ScanFindingRead(ScannerModel):
    """Passive finding candidate produced without mutation requests."""

    id: UUID
    scan_id: UUID
    endpoint_url: str
    analyzer: str
    category: str
    title: str
    summary: str
    status: str
    severity: str
    confidence: float
    evidence: list[dict[str, Any]]
    remediation: list[str]
    limitations: list[str]
    created_at: datetime


class ScanEventRead(ScannerModel):
    """User-facing progress or policy event."""

    id: UUID
    scan_id: UUID
    stage: str
    level: str
    message: str
    details: dict[str, Any]
    created_at: datetime


class ScanCancelRead(ScannerModel):
    """Cancellation acknowledgement."""

    id: UUID
    cancellation_requested: bool
    status: ScanStatus
