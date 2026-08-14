"""Health, version, and dashboard endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends

from webhacking_lab import __version__
from webhacking_lab.api.dependencies import get_request_settings
from webhacking_lab.api.schemas.system import (
    AnalysisTypeDatum,
    DashboardOverview,
    HealthResponse,
    Metric,
    RecentActivity,
    RequestVolumeDatum,
    SafetyStatus,
    SeverityDatum,
    VersionResponse,
)
from webhacking_lab.core.config import Settings

router = APIRouter(tags=["system"])


def safety_status(settings: Settings) -> SafetyStatus:
    """Map internal settings to the safe public status model."""

    return SafetyStatus(
        mode="Analysis Only" if settings.analysis_only else "Controlled Execution",
        network_execution_enabled=settings.network_execution_enabled,
        ctf_mode_enabled=settings.ctf_mode_enabled,
        insecure_tls_allowed=settings.allow_insecure_tls,
        max_response_bytes=settings.max_response_bytes,
        global_requests_per_minute=settings.global_requests_per_minute,
    )


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Check application health",
)
async def health(settings: Annotated[Settings, Depends(get_request_settings)]) -> HealthResponse:
    """Return liveness plus the effective safety posture."""

    return HealthResponse(
        status="healthy",
        service=settings.app_name,
        version=__version__,
        environment=settings.environment,
        safety=safety_status(settings),
    )


@router.get(
    "/version",
    response_model=VersionResponse,
    summary="Get product and API versions",
)
async def version() -> VersionResponse:
    """Return stable build metadata."""

    return VersionResponse(
        product="WebHacking Lab",
        package="webhacking_lab",
        version=__version__,
        api_version="v1",
    )


@router.get(
    "/dashboard/overview",
    response_model=DashboardOverview,
    summary="Get the Phase 1 demonstration dashboard",
)
async def dashboard(
    settings: Annotated[Settings, Depends(get_request_settings)],
) -> DashboardOverview:
    """Return sanitized seed metrics until workspace persistence arrives in Phase 2."""

    return DashboardOverview(
        workspace_name="Local Security Workspace",
        demo_mode=True,
        safety=safety_status(settings),
        metrics=[
            Metric(label="Active projects", value=3, delta=12, trend="up"),
            Metric(label="Analyzed requests", value=148, delta=18, trend="up"),
            Metric(label="Finding candidates", value=12, delta=-4, trend="down"),
            Metric(label="Confirmed findings", value=4, delta=2, trend="up"),
            Metric(label="Scope blocks", value=7, delta=None, trend="neutral"),
        ],
        severity_distribution=[
            SeverityDatum(severity="Critical", count=0),
            SeverityDatum(severity="High", count=2),
            SeverityDatum(severity="Medium", count=6),
            SeverityDatum(severity="Low", count=4),
            SeverityDatum(severity="Info", count=9),
        ],
        request_volume=[
            RequestVolumeDatum(label="09:00", requests=12, blocked=1),
            RequestVolumeDatum(label="10:00", requests=18, blocked=0),
            RequestVolumeDatum(label="11:00", requests=14, blocked=2),
            RequestVolumeDatum(label="12:00", requests=31, blocked=1),
            RequestVolumeDatum(label="13:00", requests=26, blocked=0),
            RequestVolumeDatum(label="14:00", requests=38, blocked=2),
            RequestVolumeDatum(label="15:00", requests=27, blocked=1),
        ],
        analysis_types=[
            AnalysisTypeDatum(category="Headers", count=42),
            AnalysisTypeDatum(category="Access", count=31),
            AnalysisTypeDatum(category="XSS", count=27),
            AnalysisTypeDatum(category="Injection", count=23),
            AnalysisTypeDatum(category="JWT", count=16),
        ],
        recent_activity=[
            RecentActivity(
                id="activity-demo-1",
                kind="analysis",
                title="Search response reviewed",
                detail="Reflected input remains a hypothesis; no active test was executed.",
                occurred_at="2 min ago",
                status="review",
            ),
            RecentActivity(
                id="activity-demo-2",
                kind="scope",
                title="Out-of-scope target blocked",
                detail="The host was not present in the project allowlist.",
                occurred_at="18 min ago",
                status="blocked",
            ),
            RecentActivity(
                id="activity-demo-3",
                kind="finding",
                title="Access control evidence confirmed",
                detail="Local IDOR lab evidence was promoted to a finding.",
                occurred_at="46 min ago",
                status="completed",
            ),
            RecentActivity(
                id="activity-demo-4",
                kind="ctf",
                title="CTF hypothesis updated",
                detail="Encoding notes and one flag candidate were recorded.",
                occurred_at="1 hr ago",
                status="active",
            ),
        ],
    )
