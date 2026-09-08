"""Persist tracked CTF challenges for the CTF Workspace.

Revision ID: 20260908_0009
Revises: 20260809_0008
Create Date: 2026-09-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260908_0009"
down_revision: str | Sequence[str] | None = "20260809_0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the CTF challenge tracker table."""

    op.create_table(
        "ctf_challenges",
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
        sa.Column("event", sa.String(length=160), nullable=False),
        sa.Column("name", sa.String(length=240), nullable=False),
        sa.Column("category", sa.String(length=60), nullable=False),
        sa.Column("difficulty", sa.String(length=40), nullable=False),
        sa.Column("points", sa.Integer(), nullable=True),
        sa.Column("target_url", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("flag", sa.Text(), nullable=False),
        sa.Column("solved_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ctf_challenges")),
    )
    op.create_index(op.f("ix_ctf_challenges_event"), "ctf_challenges", ["event"], unique=False)
    op.create_index(op.f("ix_ctf_challenges_status"), "ctf_challenges", ["status"], unique=False)


def downgrade() -> None:
    """Drop the CTF challenge tracker table."""

    op.drop_index(op.f("ix_ctf_challenges_status"), table_name="ctf_challenges")
    op.drop_index(op.f("ix_ctf_challenges_event"), table_name="ctf_challenges")
    op.drop_table("ctf_challenges")
