"""CTF Workspace challenge-tracker endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.api.dependencies import get_db_session
from webhacking_lab.api.schemas.ctf import (
    CtfChallengeCreate,
    CtfChallengePatch,
    CtfChallengeRead,
)
from webhacking_lab.services.ctf import CtfService

router = APIRouter(tags=["ctf"])
Session = Annotated[AsyncSession, Depends(get_db_session)]


def _correlation_id(request: Request) -> str | None:
    value: str | None = getattr(request.state, "correlation_id", None)
    return value


@router.post(
    "/ctf/challenges",
    response_model=CtfChallengeRead,
    status_code=status.HTTP_201_CREATED,
    summary="Track a new CTF challenge",
)
async def create_challenge(
    data: CtfChallengeCreate, request: Request, session: Session
) -> CtfChallengeRead:
    return await CtfService(session).create(data, _correlation_id(request))


@router.get(
    "/ctf/challenges",
    response_model=list[CtfChallengeRead],
    summary="List tracked CTF challenges",
)
async def list_challenges(session: Session, event: str | None = None) -> list[CtfChallengeRead]:
    return await CtfService(session).list(event)


@router.get(
    "/ctf/challenges/{challenge_id}",
    response_model=CtfChallengeRead,
    summary="Get one tracked CTF challenge",
)
async def get_challenge(challenge_id: UUID, session: Session) -> CtfChallengeRead:
    return await CtfService(session).get(challenge_id)


@router.patch(
    "/ctf/challenges/{challenge_id}",
    response_model=CtfChallengeRead,
    summary="Update a tracked CTF challenge",
)
async def update_challenge(
    challenge_id: UUID, data: CtfChallengePatch, request: Request, session: Session
) -> CtfChallengeRead:
    return await CtfService(session).update(challenge_id, data, _correlation_id(request))


@router.delete(
    "/ctf/challenges/{challenge_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a tracked CTF challenge",
)
async def delete_challenge(challenge_id: UUID, request: Request, session: Session) -> Response:
    await CtfService(session).delete(challenge_id, _correlation_id(request))
    return Response(status_code=status.HTTP_204_NO_CONTENT)
