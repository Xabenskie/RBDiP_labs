from fastapi import APIRouter, Depends
from sqlalchemy import or_, and_
from typing import List

from models.project import Project, ProjectUsers, ProjectSection
from models.task import Task, TaskMessage
from models.user import User
from schemas.project import (ProjectCreate, ProjectCreateResponse, ProjectUpdate,
                             RemoveUserFromProject, UserInProject, ProjectBaseInfo,
                             GetProject, SectionsInProject, AddUserToProject)
from db import get_database, Session
from auth import get_user
from datetime import datetime, timezone

import errors

router = APIRouter()


@router.post("/",
             response_model=ProjectCreateResponse,
             responses=errors.with_errors(errors.project_name_is_not_unique()))
async def create_project(project_data: ProjectCreate,
                         user: User = Depends(get_user),
                         db: Session = Depends(get_database)):
    unique_project_name_check = db.query(Project).filter(Project.name == project_data.name).first()
    if unique_project_name_check is not None:
        raise errors.project_name_is_not_unique()
    project = Project(name=project_data.name,
                      created_by=user.id,
                      icon_id=1 if project_data.icon_id is None else project_data.icon_id)
    db.add(project)
    db.commit()
    db.add(ProjectUsers(project_id=project.id,
                        user_id=user.id))
    db.commit()
    backlog_section = ProjectSection(project_id=project.id,
                                     name="Беклог",
                                     position=1)
    db.add(backlog_section)
    to_do = ProjectSection(project_id=project.id,
                           name="Надо сделать",
                           position=2)
    db.add(to_do)
    in_work = ProjectSection(project_id=project.id,
                             name="В работе",
                             position=3)
    db.add(in_work)
    closed = ProjectSection(project_id=project.id,
                            name="Закрыта",
                            position=4)
    db.add(closed)
    db.commit()
    return ProjectCreateResponse(project_id=project.id)


@router.delete("/{project_id}",
               status_code=204,
               responses=errors.with_errors(errors.access_denied(),
                                            errors.project_not_found()))
async def delete_project(project_id: int,
                         user: User = Depends(get_user),
                         db: Session = Depends(get_database)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if project is None:
        raise errors.project_not_found()
    if project.created_by != user.id:
        raise errors.access_denied()
    project_users = db.query(ProjectUsers).filter(ProjectUsers.project_id == project_id).all()
    for project_user in project_users:
        db.delete(project_user)
    db.flush()
    sections = db.query(ProjectSection).filter(ProjectSection.project_id == project_id).all()
    tasks = db.query(Task).filter(Task.section_id.in_([section.id for section in sections])).all()
    tasks_messages = db.query(TaskMessage).filter(TaskMessage.task_id.in_([task.id for task in tasks])).all()

    for message in tasks_messages:
        db.delete(message)
    db.flush()

    for task in tasks:
        db.delete(task)
    db.flush()

    for section in sections:
        db.delete(section)
    db.flush()

    db.delete(project)
    db.commit()


@router.get("/{project_id}",
            response_model=GetProject,
            responses=errors.with_errors(errors.project_not_found(),
                                         errors.access_denied()))
async def get_project(project_id: int,
                      user: User = Depends(get_user),
                      db: Session = Depends(get_database)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if project is None:
        raise errors.project_not_found()
    if db.query(ProjectUsers).filter_by(project_id=project_id,
                                        user_id=user.id).first() is None:
        raise errors.access_denied()

    project_sections = db.query(ProjectSection).filter(ProjectSection.project_id == project_id).all()

    return GetProject(project_id=project.id,
                      name=project.name,
                      icon_id=project.icon_id,
                      created_at=project.created_at,
                      created_by=project.created_by,
                      section_ids=[SectionsInProject(section_id=section.id,
                                                     name=section.name,
                                                     position=section.position) for section in project_sections])


@router.patch("/{project_id}",
              status_code=204,
              responses=errors.with_errors(errors.project_not_found(),
                                           errors.access_denied()))
async def update_project(project_id: int,
                         update_data: ProjectUpdate,
                         user: User = Depends(get_user),
                         db: Session = Depends(get_database)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if project is None:
        raise errors.project_not_found()
    if project.created_by != user.id:
        raise errors.access_denied()

    if update_data.name is not None:
        project.name = update_data.name
    if update_data.icon_id is not None:
        project.icon_id = update_data.icon_id

    project.updated_at = datetime.now(tz=timezone.utc)

    db.commit()


@router.get("/all/",
            response_model=List[ProjectBaseInfo],
            responses=errors.with_errors())
async def get_all_projects(user: User = Depends(get_user),
                           db: Session = Depends(get_database)):
    projects = (db.query(ProjectUsers, Project)
                .filter(ProjectUsers.user_id == user.id)
                .join(Project, ProjectUsers.project_id == Project.id)
                .all())

    result = []
    for project in projects:
        sections = db.query(ProjectSection).filter(ProjectSection.project_id == project[0].project_id).all()
        result.append(ProjectBaseInfo(project_id=project[1].id,
                                      icon_id=project[1].icon_id,
                                      name=project[1].name,
                                      section_ids=[SectionsInProject(section_id=section.id,
                                                                     name=section.name,
                                                                     position=section.position) for section in sections]))
    return result


@router.get("/{project_id}/users",
            response_model=List[UserInProject],
            responses=errors.with_errors(errors.project_not_found()))
async def get_project_users(project_id: int,
                            user: User = Depends(get_user),
                            db: Session = Depends(get_database)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if project is None:
        raise errors.project_not_found()
    project_users = (db.query(ProjectUsers, User).filter(ProjectUsers.project_id == project.id).
                     join(User, ProjectUsers.user_id == User.id).all())

    return [UserInProject(user_id=project_user[0].user_id,
                          name=project_user[1].user_info.name,
                          username=project_user[1].username,
                          surname=project_user[1].user_info.surname,
                          position=project_user[1].user_info.position,
                          is_admin=True if project_user[0].user_id == project.created_by else False)
            for project_user in project_users]


@router.post("/{project_id}/users/add",
             status_code=204,
             responses=errors.with_errors(errors.project_not_found()))
async def add_users_to_project(project_id: int,
                               data: AddUserToProject,
                               user: User = Depends(get_user),
                               db: Session = Depends(get_database)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if project is None:
        raise errors.project_not_found()
    current_project_users = [project_user.user_id for project_user in
                             db.query(ProjectUsers).filter(ProjectUsers.project_id == project.id).all()]
    users = db.query(User).filter(and_(or_(User.email.in_(data.user_identification),
                                           User.username.in_(data.user_identification)
                                           ),
                                       User.id.notin_(current_project_users))).all()
    for project_user in users:
        db.add(ProjectUsers(user_id=project_user.id,
                            project_id=project.id))
    db.commit()


@router.delete("/{project_id}/users/remove",
               status_code=204,
               responses=errors.with_errors(errors.project_not_found()))
async def remove_users_from_project(project_id: int,
                                    data: RemoveUserFromProject,
                                    user: User = Depends(get_user),
                                    db: Session = Depends(get_database)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if project is None:
        raise errors.project_not_found()
    if project.created_by != user.id:
        raise errors.access_denied()

    users_for_removal = db.query(ProjectUsers).filter(ProjectUsers.user_id.in_(data.user_ids)).all()
    for rm_user in users_for_removal:
        db.delete(rm_user)
    db.commit()
