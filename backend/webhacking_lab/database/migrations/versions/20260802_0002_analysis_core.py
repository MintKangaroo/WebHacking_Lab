"""Add persisted passive analysis runs.

Revision ID: 20260802_0002
Revises: 20260802_0001
Create Date: 2026-08-02
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260802_0002"
down_revision: str | Sequence[str] | None = "20260802_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the passive analysis snapshot table."""

    op.create_table(
        "analysis_runs",
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
        sa.Column("request_id", sa.Uuid(), nullable=False),
        sa.Column("response_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("results_json", sa.JSON(), nullable=False),
        sa.Column("flow_json", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["request_id"],
            ["http_requests.id"],
            name=op.f("fk_analysis_runs_request_id_http_requests"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["response_id"],
            ["http_responses.id"],
            name=op.f("fk_analysis_runs_response_id_http_responses"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_analysis_runs")),
    )
    op.create_index(
        op.f("ix_analysis_runs_request_id"),
        "analysis_runs",
        ["request_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_analysis_runs_response_id"),
        "analysis_runs",
        ["response_id"],
        unique=False,
    )


def downgrade() -> None:
    """Remove persisted passive analysis snapshots."""

    op.drop_index(op.f("ix_analysis_runs_response_id"), table_name="analysis_runs")
    op.drop_index(op.f("ix_analysis_runs_request_id"), table_name="analysis_runs")
    op.drop_table("analysis_runs")
