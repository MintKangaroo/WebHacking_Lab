"""Schemas for the CTF Workspace challenge tracker."""

from datetime import datetime
from uuid import UUID

from pydantic import Field

from webhacking_lab.api.schemas.resources import ApiModel
from webhacking_lab.domain.enums import CtfChallengeStatus


class CtfChallengeCreate(ApiModel):
    """Create a tracked challenge; only a name is required."""

    name: str = Field(min_length=1, max_length=240)
    event: str = Field(default="", max_length=160)
    category: str = Field(default="", max_length=60)
    difficulty: str = Field(default="", max_length=40)
    points: int | None = Field(default=None, ge=0, le=100_000)
    target_url: str = Field(default="", max_length=8192)
    status: CtfChallengeStatus = CtfChallengeStatus.TODO
    notes: str = Field(default="", max_length=20_000)
    flag: str = Field(default="", max_length=2_000)


class CtfChallengePatch(ApiModel):
    """Partial update; unset fields are left unchanged."""

    name: str | None = Field(default=None, min_length=1, max_length=240)
    event: str | None = Field(default=None, max_length=160)
    category: str | None = Field(default=None, max_length=60)
    difficulty: str | None = Field(default=None, max_length=40)
    points: int | None = Field(default=None, ge=0, le=100_000)
    target_url: str | None = Field(default=None, max_length=8192)
    status: CtfChallengeStatus | None = None
    notes: str | None = Field(default=None, max_length=20_000)
    flag: str | None = Field(default=None, max_length=2_000)


class CtfChallengeRead(ApiModel):
    """A tracked challenge as returned by the API."""

    id: UUID
    name: str
    event: str
    category: str
    difficulty: str
    points: int | None
    target_url: str
    status: CtfChallengeStatus
    notes: str
    flag: str
    solved_at: datetime | None
    created_at: datetime
    updated_at: datetime
