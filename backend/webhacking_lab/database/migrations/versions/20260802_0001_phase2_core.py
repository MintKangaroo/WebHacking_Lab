"""Create Phase 2 project, scope, HTTP, and audit tables.

Revision ID: 20260802_0001
Revises:
Create Date: 2026-08-02
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "20260802_0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _entity_columns() -> list[sa.Column[Any]]:
    """Return common UUID, timestamp, version, and soft-delete columns."""

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
        sa.Column("created_by", sa.String(length=120), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    ]


def upgrade() -> None:
    """Apply the initial persisted analysis workspace schema."""

    workspace_mode = sa.Enum(
        "CTF",
        "AUTHORIZED_PENTEST",
        "LOCAL_LAB",
        name="workspacemode",
        native_enum=False,
        length=32,
    )
    analysis_mode = sa.Enum(
        "MANUAL_HTTP",
        "URL_SCAN",
        "SOURCE_CODE",
        "HYBRID",
        name="analysismode",
        native_enum=False,
        length=32,
    )
    audit_type = sa.Enum(
        "PROJECT_CREATED",
        "PROJECT_UPDATED",
        "PROJECT_DELETED",
        "WORKSPACE_CREATED",
        "WORKSPACE_UPDATED",
        "SCOPE_RULE_CREATED",
        "SCOPE_CHECKED",
        "REQUEST_IMPORTED",
        "REQUEST_CREATED",
        "REQUEST_CLONED",
        name="auditeventtype",
        native_enum=False,
        length=48,
    )

    op.create_table(
        "projects",
        *_entity_columns(),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("mode", workspace_mode, nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_projects")),
    )
    op.create_index(op.f("ix_projects_name"), "projects", ["name"], unique=False)

    op.create_table(
        "workspaces",
        *_entity_columns(),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("mode", workspace_mode, nullable=False),
        sa.Column("analysis_mode", analysis_mode, nullable=False),
        sa.Column("network_execution_enabled", sa.Boolean(), nullable=False),
        sa.Column("request_budget", sa.Integer(), nullable=False),
        sa.Column("requests_used", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_workspaces_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_workspaces")),
    )
    op.create_index(op.f("ix_workspaces_project_id"), "workspaces", ["project_id"], unique=False)

    op.create_table(
        "scope_rules",
        *_entity_columns(),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("scheme", sa.String(length=8), nullable=False),
        sa.Column("hostname", sa.String(length=253), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("path_prefix", sa.String(length=1024), nullable=False),
        sa.Column("allow_subdomains", sa.Boolean(), nullable=False),
        sa.Column("max_requests_per_minute", sa.Integer(), nullable=False),
        sa.Column("max_concurrency", sa.Integer(), nullable=False),
        sa.Column("authorization_confirmed", sa.Boolean(), nullable=False),
        sa.Column("authorization_notes", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_scope_rules_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scope_rules")),
    )
    op.create_index(
        "ix_scope_rules_project_target",
        "scope_rules",
        ["project_id", "scheme", "hostname", "port"],
        unique=False,
    )
    op.create_index(
        op.f("ix_scope_rules_project_id"),
        "scope_rules",
        ["project_id"],
        unique=False,
    )

    op.create_table(
        "http_requests",
        *_entity_columns(),
        sa.Column("workspace_id", sa.Uuid(), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("normalized_json", sa.JSON(), nullable=False),
        sa.Column("raw_http_redacted", sa.Text(), nullable=False),
        sa.Column("body_size", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name=op.f("fk_http_requests_workspace_id_workspaces"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_http_requests")),
    )
    op.create_index(
        op.f("ix_http_requests_workspace_id"),
        "http_requests",
        ["workspace_id"],
        unique=False,
    )

    op.create_table(
        "request_revisions",
        *_entity_columns(),
        sa.Column("request_id", sa.Uuid(), nullable=False),
        sa.Column("revision_number", sa.Integer(), nullable=False),
        sa.Column("normalized_json", sa.JSON(), nullable=False),
        sa.Column("change_summary", sa.String(length=240), nullable=False),
        sa.ForeignKeyConstraint(
            ["request_id"],
            ["http_requests.id"],
            name=op.f("fk_request_revisions_request_id_http_requests"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_request_revisions")),
    )
    op.create_index(
        op.f("ix_request_revisions_request_id"),
        "request_revisions",
        ["request_id"],
        unique=False,
    )

    op.create_table(
        "http_responses",
        *_entity_columns(),
        sa.Column("request_id", sa.Uuid(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("normalized_json", sa.JSON(), nullable=False),
        sa.Column("body_size", sa.Integer(), nullable=False),
        sa.Column("elapsed_ms", sa.Float(), nullable=True),
        sa.ForeignKeyConstraint(
            ["request_id"],
            ["http_requests.id"],
            name=op.f("fk_http_responses_request_id_http_requests"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_http_responses")),
    )
    op.create_index(
        op.f("ix_http_responses_request_id"),
        "http_responses",
        ["request_id"],
        unique=False,
    )

    op.create_table(
        "audit_events",
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
        sa.Column("event_type", audit_type, nullable=False),
        sa.Column("actor", sa.String(length=120), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=True),
        sa.Column("workspace_id", sa.Uuid(), nullable=True),
        sa.Column("resource_type", sa.String(length=80), nullable=False),
        sa.Column("resource_id", sa.Uuid(), nullable=True),
        sa.Column("correlation_id", sa.String(length=80), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
    )
    for column in ("event_type", "project_id", "workspace_id", "resource_id"):
        op.create_index(op.f(f"ix_audit_events_{column}"), "audit_events", [column], unique=False)


def downgrade() -> None:
    """Remove the Phase 2 persistence schema."""

    for column in ("resource_id", "workspace_id", "project_id", "event_type"):
        op.drop_index(op.f(f"ix_audit_events_{column}"), table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_index(op.f("ix_http_responses_request_id"), table_name="http_responses")
    op.drop_table("http_responses")
    op.drop_index(op.f("ix_request_revisions_request_id"), table_name="request_revisions")
    op.drop_table("request_revisions")
    op.drop_index(op.f("ix_http_requests_workspace_id"), table_name="http_requests")
    op.drop_table("http_requests")
    op.drop_index(op.f("ix_scope_rules_project_id"), table_name="scope_rules")
    op.drop_index("ix_scope_rules_project_target", table_name="scope_rules")
    op.drop_table("scope_rules")
    op.drop_index(op.f("ix_workspaces_project_id"), table_name="workspaces")
    op.drop_table("workspaces")
    op.drop_index(op.f("ix_projects_name"), table_name="projects")
    op.drop_table("projects")
