from sqlalchemy import Integer, String, TIMESTAMP, ForeignKey, Boolean, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime
from models.base import Base, apply_message_type, apply_task_priority
from schemas.enums import EnumMessageType, EnumTaskPriority
from sqlalchemy.dialects.postgresql import ARRAY
from typing import List


class Task(Base):
    __tablename__ = 'task'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=True)
    section_id: Mapped[int] = mapped_column(Integer, ForeignKey('project_section.id'), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False,
                                                 server_default=func.current_timestamp())
    created_by: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)
    executor_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=True)
    priority: Mapped[EnumTaskPriority] = mapped_column(apply_task_priority, nullable=False,
                                                       server_default=EnumTaskPriority.medium)
    deadline: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    finished: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="False")
    finished_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    completion_time: Mapped[int] = mapped_column(nullable=False, server_default="0")
    tags: Mapped[List[str]] = mapped_column(ARRAY(String), nullable=True)


class TaskMessage(Base):
    __tablename__ = 'task_message'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("task.id"), nullable=False, index=True)
    message_type: Mapped[EnumMessageType] = mapped_column(apply_message_type,
                                                          nullable=False)
    text: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False,
                                                 server_default=func.current_timestamp())
