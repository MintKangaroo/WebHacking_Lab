"""Add bounded passive scanner jobs and inventories.

Revision ID: 20260802_0003
Revises: 20260802_0002
Create Date: 2026-08-02
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "20260802_0003"
down_revision: str | Sequence[str] | None = "20260802_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _entity_columns() -> list[sa.Column[Any]]:
    return [
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    ]


def _versioned_columns() -> list[sa.Column[Any]]:
    return [
        *_entity_columns(),
        sa.Column("created_by", sa.String(length=120), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    ]


def upgrade() -> None:
    """Create scanner job, inventory, candidate, and event tables."""

    scanner_profile = sa.Enum(
        "PASSIVE", "SAFE", "CTF", "LOCAL_LAB", name="scannerprofile", native_enum=False
    )
    scan_status = sa.Enum(
        "QUEUED",
        "VALIDATING_SCOPE",
        "CRAWLING",
        "FINGERPRINTING",
        "PASSIVE_ANALYSIS",
        "PLANNING_ACTIVE_TESTS",
        "WAITING_FOR_APPROVAL",
        "ACTIVE_TESTING",
        "VERIFYING",
        "REPORTING",
        "COMPLETED",
        "CANCELLED",
        "FAILED",
        "BLOCKED",
        name="scanstatus",
        native_enum=False,
    )
    op.create_table(
        "scan_jobs",
        *_versioned_columns(),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("workspace_id", sa.Uuid(), nullable=False),
        sa.Column("profile", scanner_profile, nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("status", scan_status, nullable=False),
        sa.Column("current_stage", sa.String(length=80), nullable=False),
        sa.Column("progress", sa.Float(), nullable=False),
        sa.Column("request_budget", sa.Integer(), nullable=False),
        sa.Column("requests_used", sa.Integer(), nullable=False),
        sa.Column("findings_count", sa.Integer(), nullable=False),
        sa.Column("cancellation_requested", sa.Boolean(), nullable=False),
        sa.Column("crawl_policy_json", sa.JSON(), nullable=False),
        sa.Column("fingerprint_json", sa.JSON(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            ondelete="CASCADE",
            name=op.f("fk_scan_jobs_project_id_projects"),
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            ondelete="CASCADE",
            name=op.f("fk_scan_jobs_workspace_id_workspaces"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_jobs")),
    )
    for column in ("project_id", "workspace_id", "status"):
        op.create_index(op.f(f"ix_scan_jobs_{column}"), "scan_jobs", [column], unique=False)

    op.create_table(
        "scan_endpoints",
        *_entity_columns(),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("depth", sa.Integer(), nullable=False),
        sa.Column("fetched", sa.Boolean(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("content_type", sa.String(length=160), nullable=True),
        sa.Column("title", sa.String(length=300), nullable=True),
        sa.Column("http_request_id", sa.Uuid(), nullable=True),
        sa.Column("http_response_id", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scan_jobs.id"],
            ondelete="CASCADE",
            name=op.f("fk_scan_endpoints_scan_id_scan_jobs"),
        ),
        sa.ForeignKeyConstraint(
            ["http_request_id"],
            ["http_requests.id"],
            ondelete="SET NULL",
            name=op.f("fk_scan_endpoints_http_request_id_http_requests"),
        ),
        sa.ForeignKeyConstraint(
            ["http_response_id"],
            ["http_responses.id"],
            ondelete="SET NULL",
            name=op.f("fk_scan_endpoints_http_response_id_http_responses"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_endpoints")),
        sa.UniqueConstraint("scan_id", "method", "url", name="uq_scan_endpoint_identity"),
    )
    for column in ("scan_id", "http_request_id", "http_response_id"):
        op.create_index(
            op.f(f"ix_scan_endpoints_{column}"), "scan_endpoints", [column], unique=False
        )

    op.create_table(
        "scan_parameters",
        *_entity_columns(),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("endpoint_url", sa.Text(), nullable=False),
        sa.Column("name", sa.String(length=300), nullable=False),
        sa.Column("location", sa.String(length=32), nullable=False),
        sa.Column("sample_value", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scan_jobs.id"],
            ondelete="CASCADE",
            name=op.f("fk_scan_parameters_scan_id_scan_jobs"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_parameters")),
        sa.UniqueConstraint(
            "scan_id", "endpoint_url", "name", "location", name="uq_scan_parameter_identity"
        ),
    )
    op.create_index(
        op.f("ix_scan_parameters_scan_id"), "scan_parameters", ["scan_id"], unique=False
    )

    op.create_table(
        "scan_findings",
        *_entity_columns(),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("endpoint_url", sa.Text(), nullable=False),
        sa.Column("analyzer", sa.String(length=100), nullable=False),
        sa.Column("category", sa.String(length=80), nullable=False),
        sa.Column("title", sa.String(length=240), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=24), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence_json", sa.JSON(), nullable=False),
        sa.Column("remediation_json", sa.JSON(), nullable=False),
        sa.Column("limitations_json", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scan_jobs.id"],
            ondelete="CASCADE",
            name=op.f("fk_scan_findings_scan_id_scan_jobs"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_findings")),
        sa.UniqueConstraint("scan_id", "endpoint_url", "analyzer", name="uq_scan_finding_identity"),
    )
    op.create_index(op.f("ix_scan_findings_scan_id"), "scan_findings", ["scan_id"], unique=False)

    op.create_table(
        "scan_events",
        *_entity_columns(),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("stage", sa.String(length=80), nullable=False),
        sa.Column("level", sa.String(length=16), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("details_json", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scan_jobs.id"],
            ondelete="CASCADE",
            name=op.f("fk_scan_events_scan_id_scan_jobs"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_events")),
    )
    op.create_index(op.f("ix_scan_events_scan_id"), "scan_events", ["scan_id"], unique=False)


def downgrade() -> None:
    """Remove scanner persistence in dependency order."""

    op.drop_index(op.f("ix_scan_events_scan_id"), table_name="scan_events")
    op.drop_table("scan_events")
    op.drop_index(op.f("ix_scan_findings_scan_id"), table_name="scan_findings")
    op.drop_table("scan_findings")
    op.drop_index(op.f("ix_scan_parameters_scan_id"), table_name="scan_parameters")
    op.drop_table("scan_parameters")
    for column in ("http_response_id", "http_request_id", "scan_id"):
        op.drop_index(op.f(f"ix_scan_endpoints_{column}"), table_name="scan_endpoints")
    op.drop_table("scan_endpoints")
    for column in ("status", "workspace_id", "project_id"):
        op.drop_index(op.f(f"ix_scan_jobs_{column}"), table_name="scan_jobs")
    op.drop_table("scan_jobs")
