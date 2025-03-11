from fastapi import APIRouter, Depends, Request, Response, Body, Cookie, status
from sqlalchemy.orm import undefer_group
from sqlalchemy import or_

import errors
from auth import get_user_session, init_user_tokens, refresh_user_tokens
from db import Session, get_database
from models.user import User, UserInfo, UnverifiedUser
from models.project import ProjectUsers
from schemas.auth import Refresh, AccountCredentials, SignUpCredentials

router = APIRouter()


@router.post("/login",
             response_model=Refresh,
             responses=errors.with_errors(errors.invalid_credentials()
))
async def login(
        request: Request,
        response: Response,
        credentials: AccountCredentials,
        db: Session = Depends(get_database)
):
    user: User | None = (db.query(User).options(undefer_group("sensitive"))
                         .filter(or_(User.email == credentials.login.lower(),
                                     User.username == credentials.login))
                         .first())
    if user is None:
        raise errors.invalid_credentials()
    if not user.verify_password(credentials.password):
        raise errors.invalid_credentials()
    return init_user_tokens(user,
                            credentials.remember_me,
                            request,
                            response,
                            db)


@router.post("/refresh",
             response_model=Refresh,
             responses=errors.with_errors(errors.unauthorized(),
                                          errors.token_expired(),
                                          errors.token_validation_failed()))
async def refresh_token(request: Request,
                        response: Response,
                        access: str = Cookie(None),
                        params: Refresh = Body(),
                        db: Session = Depends(get_database)):
    return refresh_user_tokens(access, params.refresh, request, response, db)


@router.delete("/logout", status_code=status.HTTP_204_NO_CONTENT,
               responses=errors.with_errors(errors.unauthorized(),
                                            errors.token_expired(),
                                            errors.token_validation_failed()))
async def logout_user(response: Response,
                      session=Depends(get_user_session),
                      db: Session = Depends(get_database)):
    response.delete_cookie(key="access")
    db.delete(session)
    db.commit()


@router.post("/signup",
             status_code=201,
             responses=errors.with_errors(errors.password_too_weak(),
                                          errors.auth_data_is_not_unique()))
async def sign_up(credentials: SignUpCredentials,
                  db: Session = Depends(get_database)):
    # check password length
    if len(credentials.password) < 5:
        raise errors.password_too_weak()
    # check if username and email is unique
    credentials_check = db.query(User).filter(or_(User.email == credentials.email.lower(),
                                                  User.username == credentials.username)).first()
    if credentials_check is not None:
        raise errors.auth_data_is_not_unique()
    # Inserting base and additional user data in db
    try:
        base_info = User(username=credentials.username,
                         password=credentials.password,
                         email=credentials.email)
        db.add(base_info)
        db.flush()
        additional_info = UserInfo(user_id=base_info.id,
                                   surname=credentials.surname,
                                   name=credentials.name)
        db.add(additional_info)
        db.commit()
    except Exception as e:
        db.rollback()

    # If user was invited to projects before signup, then add user to projects
    unverified_data = db.query(UnverifiedUser).filter_by(email=credentials.email).first()
    if unverified_data is not None:
        for project_id in unverified_data.project_ids:
            db.add(ProjectUsers(project_id=project_id,
                                user_id=base_info.id))
        db.delete(unverified_data)
        db.commit()
