from fastapi import APIRouter, Depends
from typing import List

from models.user import User, UserInfo
from models.project import ProjectUsers, ProjectSection
from db import get_database, Session
from auth import get_user

import errors
from models.project import Project, ProjectSection, ProjectUsers
from models.task import Task, TaskMessage
from schemas.task import CreateTaskRequest, GetTaskResponse, \
                        GetTaskInfo, UpdateTaskRequest, TaskMessage as TM, CreateTask, UserInfoSchema
from schemas.enums import EnumMessageType

router = APIRouter()


@router.post("/",
             status_code=201,
             response_model=CreateTask,
             responses=errors.with_errors(errors.access_denied()))
async def create_task(request: CreateTaskRequest,
                      user: User = Depends(get_user),
                      db: Session = Depends(get_database)):
    # check if user is on project
    user_in_project = db.query(ProjectUsers).filter(ProjectUsers.project_id == request.project_id,
                                                    ProjectUsers.user_id == user.id).first()
    if user_in_project is None:
        raise errors.access_denied()
    # check if section matches section
    section = db.query(ProjectSection).filter(ProjectSection.project_id == request.project_id,
                                              ProjectSection.id == request.section_id).first()
    if section is None:
        raise errors.section_is_not_found()

    task = Task()
    task.section_id = request.section_id
    task.name = request.name
    task.created_by = user.id
    task.executor_id = request.executor_id
    if request.description:
        task.description = request.description
    if request.priority:
        task.priority = request.priority
    if request.deadline:
        task.deadline = request.deadline
    if request.finished:
        task.finished = request.finished
    if request.finished_at:
        task.finished_at = request.finished_at
    if request.completion_time:
        task.completion_time = request.completion_time
    if request.tags:
        task.tags = request.tags
    db.add(task)
    db.flush()
    db.commit()
    return CreateTask(task_id=task.id)


@router.get("/{task_id}",
            response_model=GetTaskResponse,
            responses=errors.with_errors())
async def get_task(task_id: int,
                   user: User = Depends(get_user),
                   db: Session = Depends(get_database)):
    task = db.query(Task).filter_by(id=task_id).first()
    executor = None
    creator = None
    crtr = db.query(UserInfo).filter_by(user_id=task.created_by).first()
    exc = db.query(UserInfo).filter_by(user_id=task.executor_id).first()
    if crtr is not None:
        creator = UserInfoSchema(
            id=crtr.user_id,
            name=crtr.name,
            surname=crtr.surname
        )
    if exc is not None:
        executor = UserInfoSchema(
            id=exc.user_id,
            name=exc.name,
            surname=exc.surname
        )
    messages = []
    for msg in db.query(TaskMessage).filter_by(task_id=task_id).all():
        messages.append(TM(
            text=msg.text,
            created_at=msg.created_at
        ))
    return GetTaskResponse(
        id=task.id,
        section_id=task.section_id,
        created_at=task.created_at,
        created_by=creator,
        name=task.name,
        description=task.description,
        executor=executor,
        priority=task.priority,
        deadline=task.deadline,
        finished=task.finished,
        finished_at=task.finished_at,
        completion_time=task.completion_time,
        messages=messages,
        tags=task.tags
    )


@router.get("/all/",
            response_model=List[GetTaskInfo],
            responses=errors.with_errors())
async def get_project_tasks(project_id: int,
                            user: User = Depends(get_user),
                            db: Session = Depends(get_database)):
    tasks = []
    sections_q = db.query(ProjectSection.id).filter_by(project_id=project_id)
    for task in db.query(Task).filter(Task.section_id.in_(sections_q)).all():
        executor = None
        exc = db.query(UserInfo).filter_by(user_id=task.executor_id).first()
        if exc is not None:
            executor = UserInfoSchema(
                id=exc.user_id,
                name=exc.name,
                surname=exc.surname
            )
        tasks.append(GetTaskInfo(
            id=task.id,
            section_id=task.section_id,
            name=task.name,
            description=task.description,
            executor=executor,
            deadline=task.deadline,
            finished=task.finished,
            completion_time=task.completion_time,
            tags=task.tags
        ))
    return tasks


@router.patch("/{task_id}",
              status_code=204,
              responses=errors.with_errors())
async def update_task(task_id: int,
                      request: UpdateTaskRequest,
                      user: User = Depends(get_user),
                      db: Session = Depends(get_database)):
    task = db.query(Task).filter_by(id=task_id).first()
    user_info = db.query(UserInfo).filter_by(user_id=user.id).first()
    who = user_info.name
    if user_info.surname is not None:
        who += f" {user_info.surname}"
    msgs = []
    
    if request.section_id:
        task.section_id = request.section_id
        section_name = db.query(ProjectSection.name).filter_by(id=task.section_id)
        msgs.append(TaskMessage(
            task_id=task.id,
            message_type=str(EnumMessageType.declarative),
            text=f"{who} перенёс задачу в {section_name}",
            created_by=user.id
        ))
    if request.executor_id:
        task.executor_id = request.executor_id
        executor_info = db.query(UserInfo).filter_by(user_id=task.executor_id).first()
        executor = user_info.name
        if user_info.surname is not None:
            executor += f" {executor_info.surname}"
        msgs.append(TaskMessage(
            task_id=task.id,
            message_type=str(EnumMessageType.declarative),
            text=f"{who} назначил(а) {executor} исполнителем",
            created_by=user.id
        ))
    if request.priority:
        task.priority = request.priority
    if request.deadline:
        task.deadline = request.deadline
    if request.finished:
        task.finished = request.finished
    if request.finished_at:
        task.finished_at = request.finished_at
    if request.completion_time:
        task.completion_time = request.completion_time
    if request.tags:
        task.tags = request.tags
    msg = TaskMessage()
    msg.created_by = user.id
    msg.message_type = str(EnumMessageType.declarative)
    db.add_all(msgs)
    db.commit()


@router.delete("/{task_id}",
               status_code=204,
               responses=errors.with_errors())
async def delete_task(task_id: int,
                      user: User = Depends(get_user),
                      db: Session = Depends(get_database)):
    task = db.query(Task).filter_by(id=task_id).first()
    db.delete(task)
    db.commit()


@router.post("/{task_id}/start_counter",
             status_code=204,
             responses=errors.with_errors())
async def start_task_time_tracking(task_id: int,
                                   user: User = Depends(get_user),
                                   db: Session = Depends(get_database)):
    task = db.query(Task).filter(id=task_id).first()
    task_message = TaskMessage()
    task_message.task_id = task.id
    task_message.message_type = str(EnumMessageType.inner)
    task_message.created_by = user.id
    user_info = db.query(UserInfo).filter_by(user_id=user.id).first()
    who = user_info.name
    if user_info.surname is not None:
        who += f" {user_info.surname}"
    task_message.text = f"{who} запустил(а) таймер"
    db.add(task_message)
    db.commit()


@router.put("/{task_id}/stop_counter",
            status_code=204,
            responses=errors.with_errors())
async def stop_task_time_tracking(task_id: int,
                                  user: User = Depends(get_user),
                                  db: Session = Depends(get_database)):
    task = db.query(Task).filter(id=task_id).first()
    task_message = TaskMessage()
    task_message.task_id = task.id
    task_message.message_type = str(EnumMessageType.inner)
    task_message.created_by = user.id
    user_info = db.query(UserInfo).filter_by(user_id=user.id).first()
    who = user_info.name
    if user_info.surname is not None:
        who += f" {user_info.surname}"
    task_message.text = f"{who} остановил(а) таймер"
    db.add(task_message)
    db.commit()
