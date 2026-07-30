"""System and dashboard response schemas."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictSchema(BaseModel):
    """Base API schema rejecting accidental unknown fields."""

    model_config = ConfigDict(extra="forbid")


class SafetyStatus(StrictSchema):
    """Public subset of enforced safety defaults."""

    mode: Literal["Analysis Only"]
    network_execution_enabled: bool
    insecure_tls_allowed: bool
    max_response_bytes: int
    global_requests_per_minute: int


class HealthResponse(StrictSchema):
    """Liveness and safety-state response."""

    status: Literal["healthy"]
    service: str
    version: str
    environment: str
    safety: SafetyStatus


class VersionResponse(StrictSchema):
    """Build identity response."""

    product: str
    package: str
    version: str
    api_version: str


class Metric(StrictSchema):
    """Dashboard headline metric."""

    label: str
    value: int
    delta: float | None = None
    trend: Literal["up", "down", "neutral"] = "neutral"


class SeverityDatum(StrictSchema):
    """Finding count grouped by severity."""

    severity: Literal["Critical", "High", "Medium", "Low", "Info"]
    count: int = Field(ge=0)


class RequestVolumeDatum(StrictSchema):
    """Time bucket used by the request-volume chart."""

    label: str
    requests: int = Field(ge=0)
    blocked: int = Field(ge=0)


class AnalysisTypeDatum(StrictSchema):
    """Analysis count grouped by category."""

    category: str
    count: int = Field(ge=0)


class RecentActivity(StrictSchema):
    """A safe, non-sensitive dashboard activity entry."""

    id: str
    kind: Literal["analysis", "finding", "scope", "ctf", "lab"]
    title: str
    detail: str
    occurred_at: str
    status: Literal["completed", "review", "blocked", "active"]


class DashboardOverview(StrictSchema):
    """Aggregate dashboard payload consumed by the React application."""

    workspace_name: str
    demo_mode: bool
    safety: SafetyStatus
    metrics: list[Metric]
    severity_distribution: list[SeverityDatum]
    request_volume: list[RequestVolumeDatum]
    analysis_types: list[AnalysisTypeDatum]
    recent_activity: list[RecentActivity]
