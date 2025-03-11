import pytest
import jwt
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock
from fastapi import Response, Request
from src.auth import TokenService, SessionService, errors
from db import Session

# ==== Тесты для TokenService ====

def test_encode_decode():
    """Тест кодирования и декодирования токена."""
    payload = {
        "role": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5)
    }
    token = TokenService.encode(payload)
    decoded = TokenService.decode(token, "access")
    
    assert decoded["role"] == "access"

def test_decode_expired_token():
    """Тест обработки просроченного токена."""
    expired_payload = {
        "role": "access",
        "exp": datetime.now(timezone.utc) - timedelta(minutes=1)
    }
    token = TokenService.encode(expired_payload)

    with pytest.raises(jwt.ExpiredSignatureError):
        TokenService.decode(token, "access")

def test_decode_invalid_token():
    """Тест обработки некорректного токена."""
    invalid_token = "invalid.token.string"

    with pytest.raises(errors.token_validation_failed):
        TokenService.decode(invalid_token, "access")

# ==== Тесты для SessionService ====

def test_get_user_agent_info():
    """Тест извлечения информации о User-Agent."""
    request = Mock()
    request.client = ("127.0.0.1",)
    request.headers = {"user-agent": "TestAgent/1.0"}

    user_agent_info = SessionService.get_user_agent_info(request)

    assert "TestAgent/1.0" in user_agent_info

def test_create_session():
    """Тест создания сессии пользователя."""
    request = Mock()
    request.client = ("127.0.0.1",)
    request.headers = {"user-agent": "TestAgent/1.0"}
    response = Mock()
    db = Mock(spec=Session)

    user = Mock()
    user.id = 1

    refresh_token = SessionService.create_session(user, request, True, response, db)

    assert refresh_token.refresh is not None
    db.add.assert_called_once()
    db.commit.assert_called_once()

def test_verify_user_access():
    """Тест верификации пользователя по токену."""
    request = Mock()
    request.client = ("127.0.0.1",)
    request.headers = {"user-agent": "TestAgent/1.0"}
    db = Mock(spec=Session)
    
    session = Mock()
    session.id = "session_123"
    session.fingerprint = SessionService.get_user_agent_info(request)
    session.identity = "identity_123"
    db.query.return_value.get.return_value = session

    access_token = TokenService.encode({
        "role": "access",
        "session": session.id,
        "identity": session.identity,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5)
    })

    result = SessionService.verify_user_access(access_token, request, db)

    assert result == session
