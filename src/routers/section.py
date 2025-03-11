from typing import List

from fastapi import APIRouter, Depends, status

import errors
from auth import get_user
from db import Session, get_database
from schemas.section import (
    SectionInfoSchema,
    SectionCreateSchema,
    SectionUpdateSchema
)
from models.project import ProjectSection
from models.task import Task

router = APIRouter()


@router.post("/{project_id}/sections")
async def create_section(
        project_id: int,
        section_info: SectionCreateSchema,
        db: Session = Depends(get_database),
        access=Depends(get_user)
) -> SectionInfoSchema:
    if access is None:
        raise errors.unauthorized()
    section = ProjectSection(
        project_id=project_id,
        position=section_info.position,
        name=section_info.name,
        color=section_info.color
    )

    db.add(section)
    db.commit()

    return SectionInfoSchema(
        id=section.id,
        name=section.name,
        position=section.position,
        color=section.color
    )


@router.get("/{project_id}/section")
async def get_project_sections(
        project_id: int,
        db: Session = Depends(get_database),
        access=Depends(get_user)
) -> List[SectionInfoSchema]:
    if access is None:
        raise errors.unauthorized()
    sections = db.query(ProjectSection).filter_by(project_id=project_id).all()
    return [
        SectionInfoSchema(
            id=section.id,
            name=section.name,
            position=section.position,
            color=section.color
        ) for section in sections
    ]


@router.get("/{project_id}/section/{section_id}")
async def get_section(
        project_id: int,
        section_id: int,
        db: Session = Depends(get_database),
        access=Depends(get_user)
) -> SectionInfoSchema:
    if access is None:
        raise errors.unauthorized()
    section = db.query(ProjectSection).filter_by(
        project_id=project_id,
        id=section_id
    ).first()

    if section is None:
        raise errors.section_is_not_found()

    return SectionInfoSchema(
        id=section.id,
        name=section.name,
        position=section.position,
        color=section.color
    )


@router.delete("/{project_id}/section/{section_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_section(
        project_id: int,
        section_id: int,
        db: Session = Depends(get_database),
        access=Depends(get_user)
) -> None:
    if access is None:
        raise errors.unauthorized()

    section = db.query(ProjectSection).filter_by(
        id=section_id,
        project_id=project_id
    ).first()

    if section is None:
        raise errors.section_is_not_found()

    section_tasks = db.query(Task).filter_by(
        section_id=section_id
    ).all()

    for section_task in section_tasks:
        db.delete(section_task)
    db.flush()
    db.delete(section)
    db.commit()


@router.patch("/{project_id}/section/{section_id}")
async def update_section(
    project_id: int,
    section_id: int,
    section_info: SectionUpdateSchema,
    db: Session = Depends(get_database),
    access=Depends(get_user)
) -> SectionInfoSchema:
    if access is None:
        raise errors.unauthorized()

    section = db.query(ProjectSection).filter_by(
        project_id=project_id,
        id=section_id
    ).first()

    if section is None:
        raise errors.section_is_not_found()

    if section_info.name is not None:
        section.name = section_info.name
    if section_info.color is not None:
        section.color = section_info.color
    if section_info.position is not None:
        section.position = section_info.position

    db.commit()

    return SectionInfoSchema(
        id=section.id,
        name=section.name,
        position=section.position,
        color=section.color
    )
