from __future__ import annotations

from datetime import datetime, timezone

from app.models.user import User
from app.repositories.token_blacklist_repository import TokenBlacklistRepository
from app.repositories.user_repository import UserRepository
from app.security.constants import REFRESH_TOKEN_TYPE, UserStatus
from app.security.exceptions import (
    InvalidCredentialsException,
    RefreshTokenRevokedException,
    UserInactiveException,
    UserLockedException,
    UserNotFoundException,
    UserSuspendedException,
)
from app.security.jwt import JWTManager
from app.security.password import PasswordManager
from app.security.types import TokenPair
from app.services.base_service import BaseService


class AuthService(BaseService):
    """Authentication service with login, refresh, and token lifecycle management."""

    def __init__(
        self,
        db,
        jwt_manager: JWTManager | None = None,
        password_manager: PasswordManager | None = None,
    ) -> None:
        super().__init__(db)
        self._repository = UserRepository(db)
        self._blacklist_repository = TokenBlacklistRepository(db)
        self._jwt_manager = jwt_manager or JWTManager()
        self._password_manager = password_manager or PasswordManager()

    def authenticate(self, email: str, password: str) -> TokenPair:
        user = self._repository.get_by_email(email.lower().strip())
        if user is None:
            raise InvalidCredentialsException()

        if not self._password_manager.verify_password(password, user.hashed_password):
            raise InvalidCredentialsException()

        self._ensure_user_status(user)
        self._upgrade_password_hash_if_required(user, password)

        return self._create_token_pair(user)

    def refresh_tokens(self, refresh_token: str) -> TokenPair:
        payload = self._jwt_manager.validate_token(
            refresh_token,
            expected_token_type=REFRESH_TOKEN_TYPE,
        )

        if self._blacklist_repository.is_blacklisted(str(payload.jti)):
            raise RefreshTokenRevokedException()

        user = self._repository.get_by_id(str(payload.sub))
        if user is None:
            raise UserNotFoundException()

        self._ensure_user_status(user)
        self._blacklist_repository.add(
            jti=str(payload.jti),
            token_type=REFRESH_TOKEN_TYPE,
            user_id=str(payload.sub),
            expires_at=datetime.fromtimestamp(payload.exp, tz=timezone.utc),
            reason="refresh_token_rotation",
        )

        return self._create_token_pair(user)

    def revoke_refresh_token(self, refresh_token: str) -> None:
        payload = self._jwt_manager.validate_token(
            refresh_token,
            expected_token_type=REFRESH_TOKEN_TYPE,
        )

        self._blacklist_repository.add(
            jti=str(payload.jti),
            token_type=REFRESH_TOKEN_TYPE,
            user_id=str(payload.sub),
            expires_at=datetime.fromtimestamp(payload.exp, tz=timezone.utc),
            reason="user_logout",
        )

    def _create_token_pair(self, user: User) -> TokenPair:
        access_token = self._jwt_manager.create_access_token(
            subject=user.id,
            email=user.email,
            role=user.role,
        )
        refresh_token = self._jwt_manager.create_refresh_token(
            subject=user.id,
            email=user.email,
            role=user.role,
        )

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=int(self._jwt_manager.access_token_minutes * 60),
        )

    def _ensure_user_status(self, user: User) -> None:
        if user.status == UserStatus.INACTIVE:
            raise UserInactiveException()
        if user.status == UserStatus.LOCKED:
            raise UserLockedException()
        if user.status == UserStatus.SUSPENDED:
            raise UserSuspendedException()

    def _upgrade_password_hash_if_required(self, user: User, password: str) -> None:
        if self._password_manager.needs_rehash(user.hashed_password):
            user.hashed_password = self._password_manager.hash_password(password)
            self._repository.save(user)
