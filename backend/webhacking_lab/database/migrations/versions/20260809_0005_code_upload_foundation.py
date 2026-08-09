"""Add inert source projects, file index, and static routes.

Revision ID: 20260809_0005
Revises: 20260809_0004
Create Date: 2026-08-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260809_0005"
down_revision: str | Sequence[str] | None = "20260809_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create source metadata tables; source bodies remain in artifact storage."""

    status = sa.Enum(
        "EMPTY",
        "INDEXED",
        "ANALYZING",
        "COMPLETED",
        "FAILED",
        name="codeprojectstatus",
        native_enum=False,
        length=24,
    )
    op.create_table(
        "code_projects",
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
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("status", status, nullable=False),
        sa.Column("storage_key", sa.String(length=36), nullable=False),
        sa.Column("languages_json", sa.JSON(), nullable=False),
        sa.Column("frameworks_json", sa.JSON(), nullable=False),
        sa.Column("dependency_files_json", sa.JSON(), nullable=False),
        sa.Column("warnings_json", sa.JSON(), nullable=False),
        sa.Column("total_files", sa.Integer(), nullable=False),
        sa.Column("total_bytes", sa.Integer(), nullable=False),
        sa.Column("secret_findings_count", sa.Integer(), nullable=False),
        sa.Column("analyzed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("storage_key"),
    )
    op.create_index(op.f("ix_code_projects_project_id"), "code_projects", ["project_id"])
    op.create_index(op.f("ix_code_projects_status"), "code_projects", ["status"])
    op.create_table(
        "code_files",
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
        sa.Column("relative_path", sa.String(length=1024), nullable=False),
        sa.Column("language", sa.String(length=40), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("secret_findings_count", sa.Integer(), nullable=False),
        sa.Column("warning_codes_json", sa.JSON(), nullable=False),
        sa.Column("route_count", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["code_project_id"], ["code_projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "code_project_id",
            "relative_path",
            name="uq_code_file_path",
        ),
    )
    op.create_index(op.f("ix_code_files_code_project_id"), "code_files", ["code_project_id"])
    op.create_table(
        "static_routes",
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
        sa.Column("framework", sa.String(length=60), nullable=False),
        sa.Column("methods_json", sa.JSON(), nullable=False),
        sa.Column("path", sa.String(length=1024), nullable=False),
        sa.Column("handler_name", sa.String(length=300), nullable=False),
        sa.Column("line_start", sa.Integer(), nullable=False),
        sa.Column("line_end", sa.Integer(), nullable=False),
        sa.Column("parameters_json", sa.JSON(), nullable=False),
        sa.Column("authentication_json", sa.JSON(), nullable=False),
        sa.Column("findings_json", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["code_file_id"], ["code_files.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["code_project_id"], ["code_projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_static_routes_code_file_id"), "static_routes", ["code_file_id"])
    op.create_index(
        op.f("ix_static_routes_code_project_id"),
        "static_routes",
        ["code_project_id"],
    )


def downgrade() -> None:
    """Remove source inventory metadata without touching unrelated artifacts."""

    op.drop_index(op.f("ix_static_routes_code_project_id"), table_name="static_routes")
    op.drop_index(op.f("ix_static_routes_code_file_id"), table_name="static_routes")
    op.drop_table("static_routes")
    op.drop_index(op.f("ix_code_files_code_project_id"), table_name="code_files")
    op.drop_table("code_files")
    op.drop_index(op.f("ix_code_projects_status"), table_name="code_projects")
    op.drop_index(op.f("ix_code_projects_project_id"), table_name="code_projects")
    op.drop_table("code_projects")
