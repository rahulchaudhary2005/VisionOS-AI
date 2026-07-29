# from app.security.jwt import JWTManager

# __all__ = ["JWTManager"]


from __future__ import annotations

from collections.abc import Callable

from app.api.dependencies.database import get_db
from app.repositories.user_repository import UserRepository
from app.security.exceptions import (
    InvalidTokenException,
    MissingTokenException,
    PermissionDeniedException,
    RoleRequiredException,
)
from app.security.jwt import JWTManager
from app.security.types import (
    AuthenticatedUser,
    JWTPayload,
)
from app.services.authorization_service import AuthorizationService
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

bearer_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="Bearer Authentication",
)


def get_authenticated_payload(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> JWTPayload:
    """
    Validate the incoming JWT and return its decoded payload.
    """

    if credentials is None:
        raise MissingTokenException()

    if credentials.scheme.lower() != "bearer":
        raise MissingTokenException()

    jwt_manager = JWTManager()

    return jwt_manager.validate_token(credentials.credentials)


def get_current_user(
    payload: JWTPayload = Depends(get_authenticated_payload),
    db: Session = Depends(get_db),
) -> AuthenticatedUser:
    """
    Resolve the authenticated user from the validated JWT.
    """

    repository = UserRepository(db)

    user = repository.get_by_id(str(payload.sub))

    if user is None:
        raise InvalidTokenException()

    return AuthenticatedUser(
        id=user.id,
        email=user.email,
        full_name=user.full_name or "",
        role=user.role,
        is_active=user.is_active(),
        is_verified=user.is_verified,
        is_superuser=user.is_superuser,
    )


def get_authorization_service(
    db: Session = Depends(get_db),
) -> AuthorizationService:
    """
    Dependency provider for the authorization service.
    """

    return AuthorizationService(db)


def require_role(required_role: str) -> Callable:
    """
    Dependency enforcing a required role.
    """

    def dependency(
        current_user: AuthenticatedUser = Depends(get_current_user),
        authorization: AuthorizationService = Depends(get_authorization_service),
    ) -> AuthenticatedUser:

        if not authorization.has_role(
            current_user=current_user,
            required_role=required_role,
        ):
            raise RoleRequiredException()

        return current_user

    return dependency


def require_any_role(*roles: str) -> Callable:
    """
    Allow access if the user has at least one of the supplied roles.
    """

    def dependency(
        current_user: AuthenticatedUser = Depends(get_current_user),
        authorization: AuthorizationService = Depends(get_authorization_service),
    ) -> AuthenticatedUser:

        if not authorization.has_any_role(
            current_user=current_user,
            required_roles=list(roles),
        ):
            raise RoleRequiredException()

        return current_user

    return dependency


def require_permission(permission: str) -> Callable:
    """
    Dependency enforcing a specific permission.
    """

    def dependency(
        current_user: AuthenticatedUser = Depends(get_current_user),
        authorization: AuthorizationService = Depends(get_authorization_service),
    ) -> AuthenticatedUser:

        if not authorization.has_permission(
            current_user=current_user,
            permission=permission,
        ):
            raise PermissionDeniedException()

        return current_user

    return dependency


def require_permissions(*permissions: str) -> Callable:
    """
    Require multiple permissions.
    """

    def dependency(
        current_user: AuthenticatedUser = Depends(get_current_user),
        authorization: AuthorizationService = Depends(get_authorization_service),
    ) -> AuthenticatedUser:

        if not authorization.has_permissions(
            current_user=current_user,
            permissions=list(permissions),
        ):
            raise PermissionDeniedException()

        return current_user

    return dependency


__all__ = [
    "get_authenticated_payload",
    "get_current_user",
    "get_authorization_service",
    "require_role",
    "require_any_role",
    "require_permission",
    "require_permissions",
]
