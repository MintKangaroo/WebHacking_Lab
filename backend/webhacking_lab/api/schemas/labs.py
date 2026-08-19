"""Catalog schemas for the isolated, intentionally vulnerable training labs."""

from webhacking_lab.api.schemas.resources import ApiModel


class LabInfo(ApiModel):
    """Metadata describing one isolated training target."""

    id: str
    name: str
    category: str
    difficulty: str
    description: str
    base_url: str
    target_path: str
    objective: str
    hint: str


class LabCatalog(ApiModel):
    """The available training labs plus whether they are expected to be running."""

    enabled: bool
    warning: str
    labs: list[LabInfo]
