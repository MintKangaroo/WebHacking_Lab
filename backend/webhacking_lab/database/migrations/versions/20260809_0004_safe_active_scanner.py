"""Add individually approved SAFE scanner test cases.

Revision ID: 20260809_0004
Revises: 20260802_0003
Create Date: 2026-08-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260809_0004"
down_revision: str | Sequence[str] | None = "20260802_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the immutable preview and evidence table."""

    test_status = sa.Enum(
        "PREVIEW",
        "APPROVED",
        "RUNNING",
        "COMPLETED",
        "INCONCLUSIVE",
        "BLOCKED",
        name="activeteststatus",
        native_enum=False,
    )
    op.create_table(
        "scan_test_cases",
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
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("plugin_id", sa.String(length=100), nullable=False),
        sa.Column("category", sa.String(length=80), nullable=False),
        sa.Column("endpoint_url", sa.Text(), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=240), nullable=False),
        sa.Column("objective", sa.Text(), nullable=False),
        sa.Column("parameter", sa.String(length=300), nullable=True),
        sa.Column("mutation_type", sa.String(length=80), nullable=False),
        sa.Column("preview_value", sa.Text(), nullable=False),
        sa.Column("exact_request_preview", sa.Text(), nullable=False),
        sa.Column("expected_signals_json", sa.JSON(), nullable=False),
        sa.Column("success_criteria", sa.Text(), nullable=False),
        sa.Column("false_positive_notes", sa.Text(), nullable=False),
        sa.Column("remediation_json", sa.JSON(), nullable=False),
        sa.Column("risk_level", sa.String(length=24), nullable=False),
        sa.Column("maximum_requests", sa.Integer(), nullable=False),
        sa.Column("destructive", sa.Boolean(), nullable=False),
        sa.Column("requires_confirmation", sa.Boolean(), nullable=False),
        sa.Column("status", test_status, nullable=False),
        sa.Column("baseline_request_id", sa.Uuid(), nullable=False),
        sa.Column("baseline_response_id", sa.Uuid(), nullable=False),
        sa.Column("test_request_id", sa.Uuid(), nullable=True),
        sa.Column("test_response_id", sa.Uuid(), nullable=True),
        sa.Column("result_status", sa.String(length=32), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("evidence_json", sa.JSON(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scan_jobs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["baseline_request_id"], ["http_requests.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["baseline_response_id"], ["http_responses.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["test_request_id"], ["http_requests.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["test_response_id"], ["http_responses.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in (
        "scan_id",
        "plugin_id",
        "status",
        "baseline_request_id",
        "baseline_response_id",
        "test_request_id",
        "test_response_id",
    ):
        op.create_index(op.f(f"ix_scan_test_cases_{column}"), "scan_test_cases", [column])


def downgrade() -> None:
    """Remove SAFE test previews and captured evidence."""

    for column in (
        "test_response_id",
        "test_request_id",
        "baseline_response_id",
        "baseline_request_id",
        "status",
        "plugin_id",
        "scan_id",
    ):
        op.drop_index(op.f(f"ix_scan_test_cases_{column}"), table_name="scan_test_cases")
    op.drop_table("scan_test_cases")
