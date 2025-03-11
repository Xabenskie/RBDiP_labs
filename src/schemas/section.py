from typing import Optional

from pydantic import BaseModel


class SectionInfoSchema(BaseModel):
    id: int
    name: str
    position: int
    color: int


class SectionCreateSchema(BaseModel):
    name: str
    position: int
    color: int


class SectionUpdateSchema(BaseModel):
    name: Optional[str]
    position: Optional[int]
    color: Optional[int]
