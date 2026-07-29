# from __future__ import annotations

# from app.api.dependencies.database import get_db
# from app.repositories.user_repository import UserRepository
# from app.security.dependencies import JWTManager
# from app.security.exceptions import (
#     InvalidTokenException,
#     MissingTokenException,
#     PermissionDeniedException,
# )
# from app.security.types import AuthenticatedUser, JWTPayload
# from fastapi import Depends
# from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
# from sqlalchemy.orm import Session

# bearer_scheme = HTTPBearer(auto_error=False)


# def get_authenticated_payload(
#     credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
#     db: Session = Depends(get_db),
# ) -> JWTPayload:
#     if credentials is None or credentials.scheme.lower() != "bearer":
#         raise MissingTokenException()

#     jwt_manager = JWTManager()
#     payload = jwt_manager.validate_token(credentials.credentials)
#     return payload


# def get_current_user(
#     payload: JWTPayload = Depends(get_authenticated_payload),
#     db: Session = Depends(get_db),
# ) -> AuthenticatedUser:
#     user = UserRepository(db).get_by_id(str(payload.sub))
#     if user is None:
#         raise InvalidTokenException()

#     return AuthenticatedUser(
#         id=user.id,
#         email=user.email,
#         full_name=user.full_name or "",
#         role=user.role,
#         is_active=user.is_active(),
#         is_verified=user.is_verified,
#         is_superuser=user.is_superuser,
#     )


# def require_role(role: str):
#     def dependency(
#         current_user: AuthenticatedUser = Depends(get_current_user),
#     ) -> AuthenticatedUser:
#         if current_user.role.value != role:
#             raise PermissionDeniedException()
#         return current_user

#     return dependency


# def require_permission(permission: str):
#     def dependency(
#         current_user: AuthenticatedUser = Depends(get_current_user),
#     ) -> AuthenticatedUser:
#         if current_user.role == "admin":
#             return current_user
#         raise PermissionDeniedException()

#     return dependency

"""
===============================================================================
VisionOS AI - Authentication & Authorization Dependencies
===============================================================================

Production-grade FastAPI dependency injection for authentication,
authorization, RBAC, and permission enforcement.

Responsibilities
----------------
• OAuth2 Bearer authentication
• JWT validation
• Current user resolution
• Active account enforcement
• Role-based authorization
• Permission-based authorization
• Enterprise dependency factories

Architecture
------------
Request
    │
    ▼
OAuth2 Bearer
    │
    ▼
JWTManager
    │
    ▼
AuthorizationService
    │
    ▼
UserRepository
    │
    ▼
Protected Endpoint

===============================================================================
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.auth.authorization_service import AuthorizationService
from app.database.database import get_db
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.auth.roles import UserRole

from app.security.constants import (
    ACCESS_TOKEN_TYPE,
    #UserRole,
    UserStatus,
)

from app.security.exceptions import (
    AuthenticationServiceException,
    InvalidTokenException,
    PermissionDeniedException,
    RoleRequiredException,
    UserInactiveException,
    UserLockedException,
    UserNotFoundException,
    UserSuspendedException,
)

from app.security.jwt import JWTManager

###############################################################################
# OAuth2 Scheme
###############################################################################

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login",
    auto_error=True,
)

###############################################################################
# Dependency Factories
###############################################################################


def get_jwt_manager() -> JWTManager:
    """
    Returns singleton-compatible JWT manager.

    Can later be replaced by DI container.
    """
    return JWTManager()


def get_authorization_service(
    db: Session = Depends(get_db),
) -> AuthorizationService:
    """
    Returns AuthorizationService.

    One instance per request.
    """
    return AuthorizationService(db)


def get_user_repository(
    db: Session = Depends(get_db),
) -> UserRepository:
    """
    Repository dependency.
    """
    return UserRepository(db)


###############################################################################
# JWT Validation
###############################################################################


def get_current_token_payload(
    token: str = Depends(oauth2_scheme),
    jwt_manager: JWTManager = Depends(get_jwt_manager),
):
    """
    Validates access token.

    Returns
    -------
    JWTPayload
    """

    if not token:
        raise InvalidTokenException()

    return jwt_manager.validate_token(
        token=token,
        expected_token_type=ACCESS_TOKEN_TYPE,
    )


###############################################################################
# Current User Dependency
###############################################################################


def get_current_user(
    payload=Depends(get_current_token_payload),
    repository: UserRepository = Depends(get_user_repository),
) -> User:
    """
    Returns authenticated user.
    """

    user = repository.get_by_id(str(payload.sub))

    if user is None:
        raise UserNotFoundException()

    return user

###############################################################################
# Active User Dependency
###############################################################################


def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Ensures the authenticated account is allowed
    to access protected resources.
    """

    if current_user.status == UserStatus.LOCKED:
        raise UserLockedException()

    if current_user.status == UserStatus.SUSPENDED:
        raise UserSuspendedException()

    if current_user.status != UserStatus.ACTIVE:
        raise UserInactiveException()

    return current_user


###############################################################################
# Verified User Dependency
###############################################################################


def get_current_verified_user(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """
    Returns an authenticated, active and verified user.
    """

    if not current_user.is_verified:
        raise UserInactiveException()

    return current_user


###############################################################################
# Superuser Dependency
###############################################################################


def get_current_superuser(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """
    Returns the authenticated superuser.
    """

    if not current_user.is_superuser:
        raise PermissionDeniedException()

    return current_user


###############################################################################
# Role Dependencies
###############################################################################


def require_role(
    role: UserRole,
) -> Callable:
    """
    Require a specific role.

    Example
    -------
    @router.get(
        "/admin",
        dependencies=[
            Depends(require_role(UserRole.ADMIN))
        ],
    )
    """

    def dependency(
        current_user: User = Depends(get_current_active_user),
        authorization: AuthorizationService = Depends(
            get_authorization_service,
        ),
    ) -> User:

        if not authorization.has_role(
            current_user.id,
            role.value,
        ):
            raise RoleRequiredException(role.value)

        return current_user

    return dependency


def require_any_role(
    *roles: UserRole,
) -> Callable:
    """
    Require one of multiple roles.

    Example
    -------
    Depends(
        require_any_role(
            UserRole.ADMIN,
            UserRole.SECURITY_ADMIN,
        )
    )
    """

    def dependency(
        current_user: User = Depends(get_current_active_user),
        authorization: AuthorizationService = Depends(
            get_authorization_service,
        ),
    ) -> User:

        if not authorization.has_any_role(
            current_user.id,
            [role.value for role in roles],
        ):
            raise PermissionDeniedException()

        return current_user

    return dependency

###############################################################################
# Permission Dependencies
###############################################################################


def require_permission(
    permission: str,
) -> Callable:
    """
    Require a single permission.

    Example
    -------
    @router.get(
        "/documents",
        dependencies=[
            Depends(
                require_permission(
                    "documents:read"
                )
            )
        ],
    )
    """

    def dependency(
        current_user: User = Depends(get_current_active_user),
        authorization: AuthorizationService = Depends(
            get_authorization_service,
        ),
    ) -> User:

        if not authorization.has_permission(
            current_user.id,
            permission,
        ):
            raise PermissionDeniedException()

        return current_user

    return dependency


def require_permissions(
    *permissions: str,
) -> Callable:
    """
    Require multiple permissions.

    Every permission supplied must be granted.

    Example
    -------
    Depends(
        require_permissions(
            "documents:create",
            "documents:delete",
        )
    )
    """

    def dependency(
        current_user: User = Depends(get_current_active_user),
        authorization: AuthorizationService = Depends(
            get_authorization_service,
        ),
    ) -> User:

        if not authorization.has_permissions(
            current_user.id,
            [permission for permission in permissions],
        ):
            raise PermissionDeniedException()

        return current_user

    return dependency


###############################################################################
# Optional Role Helpers
###############################################################################


def require_admin() -> Callable:
    """
    Convenience dependency for administrators.
    """

    return require_any_role(
        UserRole.ADMIN,
        UserRole.SUPER_ADMIN,
    )


def require_super_admin() -> Callable:
    """
    Convenience dependency for super administrators.
    """

    return require_role(
        UserRole.SUPER_ADMIN,
    )


###############################################################################
# Authorization Service Dependency
###############################################################################


def get_current_authorization(
    authorization: AuthorizationService = Depends(
        get_authorization_service,
    ),
) -> AuthorizationService:
    """
    Exposes AuthorizationService to route handlers.
    """

    return authorization


###############################################################################
# Current User + Authorization
###############################################################################


def get_current_user_with_authorization(
    current_user: User = Depends(get_current_active_user),
    authorization: AuthorizationService = Depends(
        get_authorization_service,
    ),
) -> tuple[User, AuthorizationService]:
    """
    Returns both the authenticated user and the authorization service.

    Useful for endpoints that perform several authorization
    checks without repeatedly injecting dependencies.
    """

    return (
        current_user,
        authorization,
    )

###############################################################################
# Module Exports
###############################################################################

__all__ = [
    # OAuth2
    "oauth2_scheme",

    # Dependency Factories
    "get_db",
    "get_jwt_manager",
    "get_authorization_service",
    "get_user_repository",

    # Authentication
    "get_current_token_payload",
    "get_current_user",
    "get_current_active_user",
    "get_current_verified_user",
    "get_current_superuser",

    # Authorization
    "require_role",
    "require_any_role",
    "require_permission",
    "require_permissions",

    # Convenience Helpers
    "require_admin",
    "require_super_admin",

    # Service Dependencies
    "get_current_authorization",
    "get_current_user_with_authorization",
]
