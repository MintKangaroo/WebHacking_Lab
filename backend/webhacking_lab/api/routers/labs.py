"""Read-only catalog endpoint for the isolated training labs."""

from typing import Annotated

from fastapi import APIRouter, Depends

from webhacking_lab.api.dependencies import get_request_settings
from webhacking_lab.api.schemas.labs import LabCatalog
from webhacking_lab.core.config import Settings
from webhacking_lab.labs.catalog import LAB_WARNING, list_labs

router = APIRouter(tags=["labs"])


@router.get("/labs", response_model=LabCatalog, summary="List isolated training labs")
async def get_labs(settings: Annotated[Settings, Depends(get_request_settings)]) -> LabCatalog:
    """Return the training-lab catalog and whether labs are enabled."""

    return LabCatalog(enabled=settings.labs_enabled, warning=LAB_WARNING, labs=list_labs())
