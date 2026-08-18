"""Consolidated finding-report schemas that bundle every project source."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from webhacking_lab.api.schemas.resources import ApiModel

ReportSource = Literal["static", "scanner"]


class ReportFinding(ApiModel):
    """One finding from any source, normalized for a consolidated report."""

    source: ReportSource
    origin_id: UUID
    category: str
    title: str
    severity: str
    status: str
    confidence: float
    location: str
    detail: str


class ReportSummary(ApiModel):
    """Aggregate counts across every finding in the report."""

    total: int
    by_severity: dict[str, int]
    by_category: dict[str, int]
    by_source: dict[str, int]
    by_status: dict[str, int]


class ProjectReport(ApiModel):
    """All static and scanner findings for a project, with roll-up counts."""

    project_id: UUID
    project_name: str
    generated_at: datetime
    summary: ReportSummary
    findings: list[ReportFinding]
