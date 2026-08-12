"""Persist source-only findings and explainable data-flow traces.

Revision ID: 20260809_0008
Revises: 20260809_0007
Create Date: 2026-08-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260809_0008"
down_revision: str | Sequence[str] | None = "20260809_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create static candidates separately from runtime-confirmed findings."""

    op.create_table(
        "static_findings",
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
        sa.Column("code_project_id", sa.Uuid(), nullable=False),
        sa.Column("code_file_id", sa.Uuid(), nullable=False),
        sa.Column("static_route_id", sa.Uuid(), nullable=True),
        sa.Column("category", sa.String(length=80), nullable=False),
        sa.Column("title", sa.String(length=240), nullable=False),
        sa.Column("status", sa.String(length=48), nullable=False),
        sa.Column("severity", sa.String(length=24), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("route_handler", sa.String(length=300), nullable=True),
        sa.Column("source_label", sa.Text(), nullable=False),
        sa.Column("sink_label", sa.Text(), nullable=False),
        sa.Column("parameter", sa.String(length=300), nullable=True),
        sa.Column("source_line", sa.Integer(), nullable=False),
        sa.Column("sink_line", sa.Integer(), nullable=False),
        sa.Column("sanitizers_json", sa.JSON(), nullable=False),
        sa.Column("evidence_json", sa.JSON(), nullable=False),
        sa.Column("flow_steps_json", sa.JSON(), nullable=False),
        sa.Column("remediation_json", sa.JSON(), nullable=False),
        sa.Column("limitations_json", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["code_file_id"],
            ["code_files.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["code_project_id"],
            ["code_projects.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["static_route_id"],
            ["static_routes.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_static_findings_category"),
        "static_findings",
        ["category"],
    )
    op.create_index(
        op.f("ix_static_findings_code_file_id"),
        "static_findings",
        ["code_file_id"],
    )
    op.create_index(
        op.f("ix_static_findings_code_project_id"),
        "static_findings",
        ["code_project_id"],
    )
    op.create_index(
        op.f("ix_static_findings_static_route_id"),
        "static_findings",
        ["static_route_id"],
    )
    op.create_index(
        op.f("ix_static_findings_status"),
        "static_findings",
        ["status"],
    )


def downgrade() -> None:
    """Remove static source findings."""

    op.drop_index(op.f("ix_static_findings_status"), table_name="static_findings")
    op.drop_index(op.f("ix_static_findings_static_route_id"), table_name="static_findings")
    op.drop_index(op.f("ix_static_findings_code_project_id"), table_name="static_findings")
    op.drop_index(op.f("ix_static_findings_code_file_id"), table_name="static_findings")
    op.drop_index(op.f("ix_static_findings_category"), table_name="static_findings")
    op.drop_table("static_findings")
