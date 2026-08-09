"""Align persisted scanner enum string lengths with ORM declarations.

Revision ID: 20260809_0006
Revises: 20260809_0005
Create Date: 2026-08-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260809_0006"
down_revision: str | Sequence[str] | None = "20260809_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _profile_type(length: int) -> sa.Enum:
    return sa.Enum(
        "PASSIVE",
        "SAFE",
        "CTF",
        "LOCAL_LAB",
        name="scannerprofile",
        native_enum=False,
        length=length,
    )


def _scan_status_type(length: int) -> sa.Enum:
    return sa.Enum(
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
        length=length,
    )


def _test_status_type(length: int) -> sa.Enum:
    return sa.Enum(
        "PREVIEW",
        "APPROVED",
        "RUNNING",
        "COMPLETED",
        "INCONCLUSIVE",
        "BLOCKED",
        name="activeteststatus",
        native_enum=False,
        length=length,
    )


def upgrade() -> None:
    """Widen enum-backed VARCHAR columns without changing stored values."""

    with op.batch_alter_table("scan_jobs") as batch:
        batch.alter_column(
            "profile",
            existing_type=_profile_type(9),
            type_=_profile_type(24),
            existing_nullable=False,
        )
        batch.alter_column(
            "status",
            existing_type=_scan_status_type(21),
            type_=_scan_status_type(32),
            existing_nullable=False,
        )
    with op.batch_alter_table("scan_test_cases") as batch:
        batch.alter_column(
            "status",
            existing_type=_test_status_type(12),
            type_=_test_status_type(24),
            existing_nullable=False,
        )


def downgrade() -> None:
    """Restore the historical reflected lengths for rollback compatibility."""

    with op.batch_alter_table("scan_test_cases") as batch:
        batch.alter_column(
            "status",
            existing_type=_test_status_type(24),
            type_=_test_status_type(12),
            existing_nullable=False,
        )
    with op.batch_alter_table("scan_jobs") as batch:
        batch.alter_column(
            "status",
            existing_type=_scan_status_type(32),
            type_=_scan_status_type(21),
            existing_nullable=False,
        )
        batch.alter_column(
            "profile",
            existing_type=_profile_type(24),
            type_=_profile_type(9),
            existing_nullable=False,
        )
