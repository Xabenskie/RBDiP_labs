from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

from schemas.enums import EnumTaskPriority


class UserInfoSchema(BaseModel):
    id: int
    name: str
    surname: str


class TaskMessage(BaseModel):
    text: str
    created_at: datetime


class CreateTaskRequest(BaseModel):
    project_id: int
    section_id: int
    name: str
    description: Optional[str]
    executor_id: Optional[int]
    priority: Optional[EnumTaskPriority]
    deadline: Optional[datetime]
    finished: Optional[bool]
    finished_at: Optional[datetime]
    completion_time: Optional[int]
    tags: Optional[List[str]]


class GetTaskResponse(BaseModel):
    id: int
    section_id: int
    name: str
    description: Optional[str]
    created_at: datetime
    created_by: UserInfoSchema
    executor: Optional[UserInfoSchema]
    priority: EnumTaskPriority
    deadline: Optional[datetime]
    finished: bool
    finished_at: Optional[datetime]
    completion_time: int
    tags: Optional[List[str]]


class GetTaskInfo(BaseModel):
    id: int
    section_id: int
    name: str
    description: Optional[str]
    executor: Optional[UserInfoSchema]
    deadline: Optional[datetime]
    finished: bool
    completion_time: int
    tags: Optional[List[str]]


class UpdateTaskRequest(BaseModel):
    section_id: Optional[int]
    executor_id: Optional[int]
    priority: Optional[EnumTaskPriority]
    deadline: Optional[datetime]
    finished: Optional[bool]
    finished_at: Optional[datetime]
    completion_time: Optional[int]
    tags: Optional[List[str]]

    
class CreateTask(BaseModel):
    task_id: int