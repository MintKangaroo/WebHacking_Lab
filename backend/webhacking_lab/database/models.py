"""SQLAlchemy persistence models."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from webhacking_lab.database.base import Base, TimestampedUuidMixin
from webhacking_lab.domain.enums import (
    AnalysisMode,
    AuditEventType,
    ScannerProfile,
    ScanStatus,
    WorkspaceMode,
)


class VersionedEntityMixin:
    """Common authorship, versioning, metadata, and soft-delete fields."""

    created_by: Mapped[str] = mapped_column(String(120), default="local-user")
    version: Mapped[int] = mapped_column(Integer, default=1)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSON,
        default=dict,
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Project(TimestampedUuidMixin, VersionedEntityMixin, Base):
    """Top-level authorized analysis project."""

    __tablename__ = "projects"

    name: Mapped[str] = mapped_column(String(160), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    mode: Mapped[WorkspaceMode] = mapped_column(
        Enum(WorkspaceMode, native_enum=False, length=32),
    )

    workspaces: Mapped[list["Workspace"]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
    )
    scope_rules: Mapped[list["ScopeRule"]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
    )


class Workspace(TimestampedUuidMixin, VersionedEntityMixin, Base):
    """A bounded analysis workspace within a project."""

    __tablename__ = "workspaces"

    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        index=True,
    )
    name: Mapped[str] = mapped_column(String(160))
    mode: Mapped[WorkspaceMode] = mapped_column(
        Enum(WorkspaceMode, native_enum=False, length=32),
    )
    analysis_mode: Mapped[AnalysisMode] = mapped_column(
        Enum(AnalysisMode, native_enum=False, length=32),
        default=AnalysisMode.MANUAL_HTTP,
    )
    network_execution_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    request_budget: Mapped[int] = mapped_column(Integer, default=100)
    requests_used: Mapped[int] = mapped_column(Integer, default=0)

    project: Mapped[Project] = relationship(back_populates="workspaces")
    requests: Mapped[list["HttpRequest"]] = relationship(
        back_populates="workspace",
        cascade="all, delete-orphan",
    )


class ScopeRule(TimestampedUuidMixin, VersionedEntityMixin, Base):
    """An explicitly registered URL allowlist rule."""

    __tablename__ = "scope_rules"
    __table_args__ = (
        Index(
            "ix_scope_rules_project_target",
            "project_id",
            "scheme",
            "hostname",
            "port",
        ),
    )

    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        index=True,
    )
    scheme: Mapped[str] = mapped_column(String(8))
    hostname: Mapped[str] = mapped_column(String(253))
    port: Mapped[int | None] = mapped_column(Integer)
    path_prefix: Mapped[str] = mapped_column(String(1024), default="/")
    allow_subdomains: Mapped[bool] = mapped_column(Boolean, default=False)
    max_requests_per_minute: Mapped[int] = mapped_column(Integer, default=10)
    max_concurrency: Mapped[int] = mapped_column(Integer, default=2)
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    authorization_notes: Mapped[str] = mapped_column(Text, default="")

    project: Mapped[Project] = relationship(back_populates="scope_rules")


class HttpRequest(TimestampedUuidMixin, VersionedEntityMixin, Base):
    """Redacted normalized HTTP request record."""

    __tablename__ = "http_requests"

    workspace_id: Mapped[UUID] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        index=True,
    )
    method: Mapped[str] = mapped_column(String(16))
    url: Mapped[str] = mapped_column(Text)
    normalized_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    raw_http_redacted: Mapped[str] = mapped_column(Text, default="")
    body_size: Mapped[int] = mapped_column(Integer, default=0)
    source: Mapped[str] = mapped_column(String(32), default="manual")

    workspace: Mapped[Workspace] = relationship(back_populates="requests")
    revisions: Mapped[list["RequestRevision"]] = relationship(
        back_populates="request",
        cascade="all, delete-orphan",
    )
    responses: Mapped[list["HttpResponse"]] = relationship(
        back_populates="request",
        cascade="all, delete-orphan",
    )


class RequestRevision(TimestampedUuidMixin, VersionedEntityMixin, Base):
    """Immutable redacted snapshot of a request."""

    __tablename__ = "request_revisions"

    request_id: Mapped[UUID] = mapped_column(
        ForeignKey("http_requests.id", ondelete="CASCADE"),
        index=True,
    )
    revision_number: Mapped[int] = mapped_column(Integer)
    normalized_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    change_summary: Mapped[str] = mapped_column(String(240), default="Initial revision")

    request: Mapped[HttpRequest] = relationship(back_populates="revisions")


class HttpResponse(TimestampedUuidMixin, VersionedEntityMixin, Base):
    """Imported or future guarded-execution HTTP response."""

    __tablename__ = "http_responses"

    request_id: Mapped[UUID] = mapped_column(
        ForeignKey("http_requests.id", ondelete="CASCADE"),
        index=True,
    )
    status_code: Mapped[int] = mapped_column(Integer)
    normalized_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    body_size: Mapped[int] = mapped_column(Integer, default=0)
    elapsed_ms: Mapped[float | None] = mapped_column(Float)

    request: Mapped[HttpRequest] = relationship(back_populates="responses")


class AnalysisRun(TimestampedUuidMixin, VersionedEntityMixin, Base):
    """Persisted passive analysis result and workflow graph."""

    __tablename__ = "analysis_runs"

    request_id: Mapped[UUID] = mapped_column(
        ForeignKey("http_requests.id", ondelete="CASCADE"),
        index=True,
    )
    response_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("http_responses.id", ondelete="SET NULL"),
        index=True,
    )
    status: Mapped[str] = mapped_column(String(32), default="completed")
    results_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    flow_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class ScanJob(TimestampedUuidMixin, VersionedEntityMixin, Base):
    """Bounded, cancellable passive URL scan."""

    __tablename__ = "scan_jobs"

    project_id: Mapped[UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        index=True,
    )
    workspace_id: Mapped[UUID] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        index=True,
    )
    profile: Mapped[ScannerProfile] = mapped_column(
        Enum(ScannerProfile, native_enum=False, length=24),
    )
    target: Mapped[str] = mapped_column(Text)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, native_enum=False, length=32),
        index=True,
    )
    current_stage: Mapped[str] = mapped_column(String(80), default="Queued")
    progress: Mapped[float] = mapped_column(Float, default=0)
    request_budget: Mapped[int] = mapped_column(Integer)
    requests_used: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    cancellation_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    crawl_policy_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    fingerprint_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    endpoints: Mapped[list["ScanEndpoint"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    parameters: Mapped[list["ScanParameter"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    findings: Mapped[list["ScanFinding"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    events: Mapped[list["ScanEvent"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )


class ScanEndpoint(TimestampedUuidMixin, Base):
    """Endpoint discovered from a fetched or parsed passive artifact."""

    __tablename__ = "scan_endpoints"
    __table_args__ = (
        UniqueConstraint("scan_id", "method", "url", name="uq_scan_endpoint_identity"),
    )

    scan_id: Mapped[UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        index=True,
    )
    url: Mapped[str] = mapped_column(Text)
    method: Mapped[str] = mapped_column(String(16), default="GET")
    source: Mapped[str] = mapped_column(String(40))
    depth: Mapped[int] = mapped_column(Integer, default=0)
    fetched: Mapped[bool] = mapped_column(Boolean, default=False)
    status_code: Mapped[int | None] = mapped_column(Integer)
    content_type: Mapped[str | None] = mapped_column(String(160))
    title: Mapped[str | None] = mapped_column(String(300))
    http_request_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("http_requests.id", ondelete="SET NULL"),
        index=True,
    )
    http_response_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("http_responses.id", ondelete="SET NULL"),
        index=True,
    )

    scan: Mapped[ScanJob] = relationship(back_populates="endpoints")


class ScanParameter(TimestampedUuidMixin, Base):
    """Deduplicated input observed for one scanner job."""

    __tablename__ = "scan_parameters"
    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "endpoint_url",
            "name",
            "location",
            name="uq_scan_parameter_identity",
        ),
    )

    scan_id: Mapped[UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        index=True,
    )
    endpoint_url: Mapped[str] = mapped_column(Text)
    name: Mapped[str] = mapped_column(String(300))
    location: Mapped[str] = mapped_column(String(32))
    sample_value: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(40))

    scan: Mapped[ScanJob] = relationship(back_populates="parameters")


class ScanFinding(TimestampedUuidMixin, Base):
    """Passive analyzer candidate associated with a runtime endpoint."""

    __tablename__ = "scan_findings"
    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "endpoint_url",
            "analyzer",
            name="uq_scan_finding_identity",
        ),
    )

    scan_id: Mapped[UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        index=True,
    )
    endpoint_url: Mapped[str] = mapped_column(Text)
    analyzer: Mapped[str] = mapped_column(String(100))
    category: Mapped[str] = mapped_column(String(80))
    title: Mapped[str] = mapped_column(String(240))
    summary: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(24))
    confidence: Mapped[float] = mapped_column(Float)
    evidence_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    remediation_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    limitations_json: Mapped[list[str]] = mapped_column(JSON, default=list)

    scan: Mapped[ScanJob] = relationship(back_populates="findings")


class ScanEvent(TimestampedUuidMixin, Base):
    """Append-only user-facing scan progress event."""

    __tablename__ = "scan_events"

    scan_id: Mapped[UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        index=True,
    )
    stage: Mapped[str] = mapped_column(String(80))
    level: Mapped[str] = mapped_column(String(16), default="info")
    message: Mapped[str] = mapped_column(Text)
    details_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    scan: Mapped[ScanJob] = relationship(back_populates="events")


class AuditEvent(TimestampedUuidMixin, Base):
    """Append-only event with redacted details."""

    __tablename__ = "audit_events"

    event_type: Mapped[AuditEventType] = mapped_column(
        Enum(AuditEventType, native_enum=False, length=48),
        index=True,
    )
    actor: Mapped[str] = mapped_column(String(120), default="local-user")
    project_id: Mapped[UUID | None] = mapped_column(index=True)
    workspace_id: Mapped[UUID | None] = mapped_column(index=True)
    resource_type: Mapped[str] = mapped_column(String(80))
    resource_id: Mapped[UUID | None] = mapped_column(index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(80))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
