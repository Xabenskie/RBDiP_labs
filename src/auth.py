import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Any

from fastapi import Request, Response, Cookie, Depends
from jwt import ExpiredSignatureError, DecodeError
import jwt
import errors
from models.user import User, UserSession
from schemas.auth import Refresh
from db import Session, get_database
from settings import settings

agent_parse = re.compile(r"^([\w]*)\/([\d\.]*)(?:\s*\((.*?)\))?")

def encode_jwt(payload: Dict[str, Any]) -> str:
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")

def decode_jwt(token: str, expected_role: str, suppress: bool = False) -> Dict[str, Any]:
    try:
        decoded = jwt.decode(
            token, settings.JWT_SECRET, algorithms=["HS256"],
            options={"require": ["exp", "role", "session", "type", "identity"]}
        )
        if decoded["role"] != expected_role:
            raise errors.token_validation_failed()
        return decoded
    except ExpiredSignatureError:
        if suppress:
            decoded = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"], options={"verify_signature": False})
            if decoded["role"] != expected_role:
                raise errors.token_validation_failed()
            return decoded
        raise errors.token_expired()
    except DecodeError:
        raise errors.token_validation_failed()

def create_access_token(session_id: str, identity: str) -> str:
    return encode_jwt({
        "role": "access",
        "session": session_id,
        "identity": identity,
        "type": "user",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_ACCESS_EXPIRE)
    })

def create_refresh_token(session_id: str, identity: str, is_long: bool, expires_at: datetime) -> str:
    return encode_jwt({
        "role": "refresh",
        "session": session_id,
        "identity": identity,
        "type": f"user:{is_long}",
        "exp": expires_at
    })

def get_user_agent_info(request: Request) -> str:
    user_agent = request.headers.get("user-agent", "")
    ip = request.client[0] if request.client else "unknown"
    info = [request.headers.get("X-Forwarded-For", request.headers.get("Forwarded", ip))]
    match = agent_parse.fullmatch(user_agent)
    if match:
        info += list(match.groups())
    return json.dumps(info, ensure_ascii=False)

def create_session(user: User, is_long: bool, request: Request, db: Session) -> UserSession:
    now = datetime.now(timezone.utc)
    session = UserSession(
        user_id=user.id,
        fingerprint=get_user_agent_info(request),
        identity=str(uuid.uuid1(int(now.timestamp()))),
        invalid_after=now + timedelta(hours=(
            settings.JWT_REFRESH_LONG_EXPIRE if is_long else settings.JWT_REFRESH_EXPIRE
        ))
    )
    db.add(session)
    db.commit()
    return session

def set_cookie(access: str, response: Response, max_age: int):
    response.set_cookie("access", access, httponly=True, samesite="lax", max_age=max_age)

def init_user_tokens(user: User, is_long: bool, request: Request, response: Response, db: Session) -> Refresh:
    session = create_session(user, is_long, request, db)
    access = create_access_token(session.id, session.identity)
    refresh = create_refresh_token(session.id, session.identity, is_long, session.invalid_after)
    set_cookie(access, response, settings.JWT_ACCESS_EXPIRE * 60)
    return Refresh(refresh=refresh)

def verify_user_access(access: str, request: Request, db: Session) -> UserSession:
    access_payload = decode_jwt(access, "access")
    session = db.query(UserSession).get(access_payload["session"])
    if not session or session.fingerprint != get_user_agent_info(request) or session.identity != access_payload["identity"]:
        if session:
            db.delete(session)
            db.commit()
        raise errors.unauthorized()
    return session

def refresh_user_tokens(access: str, refresh: str, request: Request, response: Response, db: Session) -> Refresh:
    access_payload = decode_jwt(access, "access", suppress=True)
    refresh_payload = decode_jwt(refresh, "refresh")
    
    if access_payload["identity"] != refresh_payload["identity"]:
        raise errors.token_validation_failed()
    
    session = db.query(UserSession).get(access_payload["session"])
    if not session or session.fingerprint != get_user_agent_info(request) or session.identity != access_payload["identity"]:
        if session:
            db.delete(session)
            db.commit()
        raise errors.unauthorized()
    
    session.identity = str(uuid.uuid1())
    is_long = refresh_payload["type"].endswith("True")
    session.invalid_after = datetime.now(timezone.utc) + timedelta(hours=(
        settings.JWT_REFRESH_LONG_EXPIRE if is_long else settings.JWT_REFRESH_EXPIRE
    ))
    db.commit()
    
    access = create_access_token(session.id, session.identity)
    refresh = create_refresh_token(session.id, session.identity, is_long, session.invalid_after)
    set_cookie(access, response, settings.JWT_ACCESS_EXPIRE * 60)
    return Refresh(refresh=refresh)

async def get_user_session(request: Request, access: str = Cookie(None), db: Session = Depends(get_database)) -> UserSession:
    return verify_user_access(access, request, db)

async def get_user(session: UserSession = Depends(get_user_session)) -> User:
    return session.user
