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
    # Evidence maturity after hybrid correlation. For a static finding this is the
    # status promoted by any matching runtime signal; for a scanner finding it is its
    # own recorded verification.
    verification: str
    # Number of findings from the other source correlated to this one.
    correlation_count: int


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


class ReportFlowStep(ApiModel):
    """One explainable step of a static source-to-sink trace."""

    kind: str
    label: str
    line: int
    detail: str


class HybridRuntimeSignal(ApiModel):
    """One runtime observation correlated to a static candidate."""

    origin_id: UUID
    kind: Literal["active_test", "passive_finding"]
    endpoint_url: str
    parameter: str | None
    verification: str
    confidence: float | None
    title: str
    evidence: list[str]


class HybridCorrelation(ApiModel):
    """A static source-to-sink candidate joined to matching runtime evidence."""

    category: str
    severity: str
    verification: str
    note: str | None
    static_origin_id: UUID
    static_title: str
    static_location: str
    parameter: str | None
    runtime: list[HybridRuntimeSignal]


class HybridReport(ApiModel):
    """Static candidates confirmed or contextualized by runtime scanner evidence."""

    project_id: UUID
    project_name: str
    generated_at: datetime
    total_static: int
    correlated: int
    by_verification: dict[str, int]
    correlations: list[HybridCorrelation]


class ReportFindingDetail(ApiModel):
    """A single finding with its full evidence and remediation for drill-down."""

    source: ReportSource
    origin_id: UUID
    category: str
    title: str
    severity: str
    status: str
    confidence: float
    location: str
    summary: str
    flow_steps: list[ReportFlowStep]
    evidence: list[str]
    remediation: list[str]
    safe_example: str | None
    limitations: list[str]
