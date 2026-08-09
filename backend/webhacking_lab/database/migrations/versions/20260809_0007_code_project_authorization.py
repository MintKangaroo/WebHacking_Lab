"""Require persisted authorization evidence for inert source uploads.

Revision ID: 20260809_0007
Revises: 20260809_0006
Create Date: 2026-08-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260809_0007"
down_revision: str | Sequence[str] | None = "20260809_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add deny-by-default authorization evidence for existing source projects."""

    op.add_column(
        "code_projects",
        sa.Column(
            "authorization_confirmed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "code_projects",
        sa.Column(
            "authorization_notes",
            sa.Text(),
            nullable=False,
            server_default="",
        ),
    )


def downgrade() -> None:
    """Remove source authorization evidence columns."""

    with op.batch_alter_table("code_projects") as batch:
        batch.drop_column("authorization_notes")
        batch.drop_column("authorization_confirmed")
