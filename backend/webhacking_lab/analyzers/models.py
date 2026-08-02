"""Typed contracts shared by every passive analyzer."""

from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from webhacking_lab.domain.enums import (
    RiskLevel,
    Severity,
    VerificationStatus,
    VulnerabilityCategory,
)
from webhacking_lab.http_client.models import NormalizedRequest, NormalizedResponse


class AnalysisModel(BaseModel):
    """Strict analysis artifact base."""

    model_config = ConfigDict(extra="forbid")


class Evidence(AnalysisModel):
    """One redacted observation supporting or limiting a hypothesis."""

    title: str
    detail: str
    location: str | None = None


class Hypothesis(AnalysisModel):
    """A claim that remains explicitly unconfirmed until evidence supports it."""

    title: str
    rationale: str
    status: VerificationStatus = VerificationStatus.NOT_TESTED


class TestCase(AnalysisModel):
    """A bounded preview that is never executed by the analysis engine."""

    title: str
    objective: str
    parameter: str | None = None
    mutation_type: str
    preview_value: str
    expected_signal: list[str]
    risk_level: RiskLevel
    requires_confirmation: bool = True
    max_requests: int = Field(default=1, ge=1, le=3)
    destructive: bool = False


class Reference(AnalysisModel):
    """Stable defensive reference identifier or URL."""

    title: str
    url: str


class AnalysisContext(AnalysisModel):
    """Immutable identifiers and safety context passed to analyzers."""

    request_id: UUID | None = None
    response_id: UUID | None = None
    network_execution_allowed: bool = False


class AnalysisResult(AnalysisModel):
    """Non-assertive result contract returned by every analyzer."""

    analyzer: str
    category: VulnerabilityCategory
    title: str
    summary: str
    evidence: list[Evidence]
    hypotheses: list[Hypothesis]
    safe_test_cases: list[TestCase]
    confidence: float = Field(ge=0, le=1)
    severity: Severity
    status: VerificationStatus
    remediation: list[str]
    references: list[Reference]
    limitations: list[str]


class FlowNode(AnalysisModel):
    """React Flow-compatible analysis stage node."""

    id: str
    label: str
    status: str
    detail: str
    confidence: float | None = Field(default=None, ge=0, le=1)


class FlowEdge(AnalysisModel):
    """Directed analysis workflow edge."""

    id: str
    source: str
    target: str


class AnalysisFlow(AnalysisModel):
    """Persisted workflow graph returned without frontend-specific coordinates."""

    nodes: list[FlowNode]
    edges: list[FlowEdge]


class Analyzer(Protocol):
    """Contract for passive, transport-independent analysis plugins."""

    name: str
    category: VulnerabilityCategory

    async def analyze(
        self,
        request: NormalizedRequest,
        response: NormalizedResponse | None,
        context: AnalysisContext,
    ) -> AnalysisResult:
        """Analyze already-collected, redacted evidence."""
