from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class ProjectCreate(BaseModel):
    name: str
    icon_id: Optional[int]


class ProjectCreateResponse(BaseModel):
    project_id: int


class ProjectUpdate(BaseModel):
    name: Optional[str]
    icon_id: Optional[int]


class RemoveUserFromProject(BaseModel):
    user_ids: List[int]


class UserInProject(BaseModel):
    user_id: int
    name: str
    surname: str
    username: str
    position: Optional[str]
    is_admin: bool


class SectionsInProject(BaseModel):
    section_id: int
    name: str
    position: int


class ProjectBaseInfo(BaseModel):
    project_id: int
    icon_id: int
    name: str
    section_ids: List[SectionsInProject]


class GetProject(BaseModel):
    project_id: int
    name: str
    icon_id: int
    created_at: datetime
    created_by: int
    section_ids: List[SectionsInProject]


class AddUserToProject(BaseModel):
    user_identification: List[str]
