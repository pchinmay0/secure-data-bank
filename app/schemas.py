from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict


class Institution(str, Enum):
    UNIVERSITY_A = "UniversityA"
    LAB_B = "LabB"


class Sensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    RESTRICTED = "restricted"


class DatasetOut(BaseModel):
    """What the API returns about a dataset. Deliberately excludes stored_filename."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    owner_institution: str
    sensitivity: str
    shared_with: list[str]
    original_filename: str
    content_type: str
    size_bytes: int
    sha256: str
    created_at: datetime