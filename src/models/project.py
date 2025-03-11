from sqlalchemy import Integer, String, TIMESTAMP, ForeignKey, Boolean, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime
from models.base import Base


class Project(Base):
    __tablename__ = 'project'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    icon_id: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False,
                                                 server_default=func.current_timestamp())
    updated_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)


class ProjectUsers(Base):
    __tablename__ = 'project_user'
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("project.id"), primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("user.id"), primary_key=True)


class ProjectSection(Base):
    __tablename__ = 'project_section'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("project.id"), index=True)
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    color: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
