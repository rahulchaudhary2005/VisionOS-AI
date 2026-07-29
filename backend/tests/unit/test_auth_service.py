import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("SECRET_KEY", "test_secret_key")
os.environ.setdefault("JWT_SECRET", "test_jwt_secret")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("OLLAMA_URL", "http://localhost")

from app.database.base import Base
from app.security.exceptions import (
    InvalidCredentialsException,
    UserAlreadyExistsException,
)
from app.services.auth_service import AuthService
from app.services.user_service import UserService


@pytest.fixture(scope="function")
def db_session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def test_register_user_creates_active_user(db_session):
    service = UserService(db_session)
    user = service.register_user(
        email="test@example.com",
        password="Str0ngP@ssword1",
        full_name="Test User",
    )

    assert user.email == "test@example.com"
    assert user.full_name == "Test User"
    assert user.is_active()
    assert user.is_verified
    assert not user.is_superuser


def test_register_user_duplicate_email_raises(db_session):
    service = UserService(db_session)
    service.register_user(
        email="test@example.com",
        password="Str0ngP@ssword1",
        full_name="Test User",
    )

    with pytest.raises(UserAlreadyExistsException):
        service.register_user(
            email="test@example.com",
            password="Str0ngP@ssword2",
            full_name="Duplicate User",
        )


def test_authenticate_success(db_session):
    user_service = UserService(db_session)
    user_service.register_user(
        email="login@example.com",
        password="Str0ngP@ssword1",
        full_name="Login User",
    )

    auth_service = AuthService(db_session)
    tokens = auth_service.authenticate("login@example.com", "Str0ngP@ssword1")

    assert tokens.access_token
    assert tokens.refresh_token
    assert tokens.expires_in > 0


def test_authenticate_invalid_password_raises(db_session):
    user_service = UserService(db_session)
    user_service.register_user(
        email="login@example.com",
        password="Str0ngP@ssword1",
        full_name="Login User",
    )

    auth_service = AuthService(db_session)

    with pytest.raises(InvalidCredentialsException):
        auth_service.authenticate("login@example.com", "WrongPassword123")


def test_refresh_tokens_rotates_refresh_token(db_session):
    user_service = UserService(db_session)
    user_service.register_user(
        email="refresh@example.com",
        password="Str0ngP@ssword1",
        full_name="Refresh User",
    )

    auth_service = AuthService(db_session)
    tokens = auth_service.authenticate("refresh@example.com", "Str0ngP@ssword1")
    refreshed = auth_service.refresh_tokens(tokens.refresh_token)

    assert refreshed.access_token != tokens.access_token
    assert refreshed.refresh_token != tokens.refresh_token
