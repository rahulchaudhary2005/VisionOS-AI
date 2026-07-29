from __future__ import annotations

from typing import Iterable

from sqlalchemy.orm import Session

from app.models.permission import Permission
from app.models.role import Role
from app.models.user import User
from app.repositories.permission_repository import PermissionRepository
from app.repositories.role_permission_repository import (
    RolePermissionRepository,
)
from app.repositories.role_repository import RoleRepository
from app.security.constants import UserRole
from app.security.exceptions import (
    PermissionDeniedException,
    RoleRequiredException,
)
from app.services.base_service import BaseService


class AuthorizationService(BaseService):
    """
    Enterprise RBAC service.

    Responsible only for authorization decisions.

    Responsibilities
    ----------------
    • Role validation
    • Permission validation
    • Permission aggregation
    • Superuser bypass

    This service intentionally contains no FastAPI code,
    no Depends(), and no HTTP knowledge.
    """

    def __init__(self, db: Session) -> None:
        super().__init__(db)

        self._role_repository = RoleRepository(db)
        self._permission_repository = PermissionRepository(db)
        self._role_permission_repository = RolePermissionRepository(db)

    # ------------------------------------------------------------------
    # Role
    # ------------------------------------------------------------------

    def require_role(
        self,
        user: User,
        required_role: UserRole,
    ) -> None:
        """
        Ensure the user possesses the required role.
        """

        if user.is_superuser:
            return

        if user.role != required_role:
            raise RoleRequiredException()

    def has_role(
        self,
        user: User,
        role: UserRole,
    ) -> bool:
        """
        Returns True if the user has the specified role.
        """

        if user.is_superuser:
            return True

        return user.role == role

    # ------------------------------------------------------------------
    # Permission
    # ------------------------------------------------------------------

    def require_permission(
        self,
        user: User,
        permission_name: str,
    ) -> None:
        """
        Raises PermissionDeniedException if the user
        does not possess the permission.
        """

        if self.has_permission(user, permission_name):
            return

        raise PermissionDeniedException()

    def has_permission(
        self,
        user: User,
        permission_name: str,
    ) -> bool:
        """
        Returns True if user owns permission.
        """

        if user.is_superuser:
            return True

        permissions = self.get_permissions(user)

        return permission_name in permissions

    # ------------------------------------------------------------------
    # Permission Discovery
    # ------------------------------------------------------------------

    def get_permissions(
        self,
        user: User,
    ) -> set[str]:
        """
        Returns every permission assigned to the user.

        Result is returned as a Python set for O(1) lookups.
        """

        role = self._find_role(user)

        if role is None:
            return set()

        role_permissions = (
            self._role_permission_repository
            .get_permissions_for_role(role.id)
        )

        if not role_permissions:
            return set()

        permission_ids = [
            rp.permission_id
            for rp in role_permissions
        ]

        permissions: Iterable[Permission] = (
            self._permission_repository
            .get_many(permission_ids)
        )

        return {
            permission.name
            for permission in permissions
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _find_role(
        self,
        user: User,
    ) -> Role | None:
        """
        Resolve the database Role entity associated
        with the user's enum role.
        """

        return self._role_repository.get_by_name(
            user.role.value
        )
