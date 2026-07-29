"""
===============================================================================
VisionOS AI - Enterprise Authorization Service
===============================================================================

Central RBAC authorization service.

Responsibilities
----------------
* Resolve user roles
* Resolve permissions
* Permission checking
* Role checking
* Super Admin bypass
* Permission caching
* Authorization helpers

Author: VisionOS AI
Architecture: Enterprise
===============================================================================
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Set

from sqlalchemy.orm import Session

from app.models.user import User
#from app.repositories.permission_repository import PermissionRepository
from app.repositories.role_permission_repository import (
    RolePermissionRepository,
)
from app.repositories.role_repository import RoleRepository
from app.repositories.user_repository import UserRepository


class AuthorizationService:
    """
    Enterprise RBAC Authorization Service.

    This class is responsible for resolving
    users, roles and permissions.

    Business logic related to authorization
    belongs here instead of repositories.
    """

    # ------------------------------------------------------------------
    # Constructor
    # ------------------------------------------------------------------

    def __init__(self, db: Session):

        self.db = db

        self.user_repository = UserRepository(db)

        self.role_repository = RoleRepository(db)

       # self.permission_repository = PermissionRepository(db)

        self.role_permission_repository = (
            RolePermissionRepository(db)
        )

        # --------------------------------------------------------------

        # In-memory permission cache.
        # Later this can be replaced by Redis.

        self._permission_cache: Dict[str, Set[str]] = {}

        self._role_cache: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Cache Helpers
    # ------------------------------------------------------------------

    def _cache_permissions(
        self,
        user_id: str,
        permissions: Set[str],
    ) -> None:
        """
        Store resolved permissions.

        Cache key:
            user_id
        """

        self._permission_cache[user_id] = permissions

    def _get_cached_permissions(
        self,
        user_id: str,
    ) -> Set[str] | None:
        """
        Returns cached permissions
        if available.
        """

        return self._permission_cache.get(user_id)

    def _cache_role(
        self,
        user_id: str,
        role_name: str,
    ) -> None:
        """
        Cache user's role.
        """

        self._role_cache[user_id] = role_name

    def _get_cached_role(
        self,
        user_id: str,
    ) -> str | None:
        """
        Returns cached role.
        """

        return self._role_cache.get(user_id)


    # ------------------------------------------------------------------
        # Database Helpers
        # ------------------------------------------------------------------

    def _get_user(
            self,
            user_id: str,
        ) -> User:
            """
            Returns user from database.

            Raises
            ------
            ValueError
                If user does not exist.
            """

            user = self.user_repository.get_by_id(user_id)

            if user is None:
                raise ValueError(
                    f"User '{user_id}' does not exist."
                )

            return user

    def _clear_user_cache(
            self,
            user_id: str,
        ) -> None:
            """
            Clears cached authorization data.
            """

            self._permission_cache.pop(user_id, None)

            self._role_cache.pop(user_id, None)

    def clear_cache(self) -> None:
            """
            Clears the entire authorization cache.
            """

            self._permission_cache.clear()

            self._role_cache.clear()


    # ------------------------------------------------------------------
    # Role Resolution
    # ------------------------------------------------------------------

    def get_user_role(
        self,
        user_id: str,
        *,
        use_cache: bool = True,
    ) -> str:
        """
        Returns the user's role name.

        Uses the in-memory cache when available.
        """

        if use_cache:
            cached = self._get_cached_role(user_id)
            if cached is not None:
                return cached

        user = self._get_user(user_id)

        role_name = user.role.name

        self._cache_role(user_id, role_name)

        return role_name

    # ------------------------------------------------------------------
    # Permission Resolution
    # ------------------------------------------------------------------

    def get_user_permissions(
        self,
        user_id: str,
        *,
        use_cache: bool = True,
    ) -> set[str]:
        """
        Returns all permissions assigned to the user's role.
        """

        if use_cache:
            cached = self._get_cached_permissions(user_id)
            if cached is not None:
                return cached

        user = self._get_user(user_id)

        permissions: set[str] = set()

        if user.role is not None:

            for mapping in user.role.permissions:

                if mapping.permission is not None:
                    permissions.add(mapping.permission.name)

        self._cache_permissions(
            user_id=user_id,
            permissions=permissions,
        )

        return permissions

    # ------------------------------------------------------------------
    # Aggregation Helpers
    # ------------------------------------------------------------------

    def get_role_permissions(
        self,
        role_name: str,
    ) -> set[str]:
        """
        Returns every permission assigned to a role.
        """

        role = self.role_repository.get_by_name(role_name)

        if role is None:
            return set()

        permissions: set[str] = set()

        for mapping in role.permissions:

            if mapping.permission is not None:
                permissions.add(mapping.permission.name)

        return permissions

    def get_permission_matrix(self) -> dict[str, set[str]]:
        """
        Returns

        {
            role_name: {
                permission1,
                permission2,
            }
        }
        """

        matrix: dict[str, set[str]] = {}

        roles = self.role_repository.list_all()

        for role in roles:

            matrix[role.name] = self.get_role_permissions(
                role.name
            )

        return matrix

    # ------------------------------------------------------------------
    # Cache Refresh
    # ------------------------------------------------------------------

    def refresh_user_permissions(
        self,
        user_id: str,
    ) -> set[str]:
        """
        Rebuilds the permission cache for a user.
        """

        self._clear_user_cache(user_id)

        return self.get_user_permissions(
            user_id,
            use_cache=False,
        )

    def refresh_role(
        self,
        user_id: str,
    ) -> str:
        """
        Refreshes the cached role.
        """

        self._role_cache.pop(user_id, None)

        return self.get_user_role(
            user_id,
            use_cache=False,
        )

        # ------------------------------------------------------------------
    # Authorization
    # ------------------------------------------------------------------

    def is_super_admin(
        self,
        user_id: str,
    ) -> bool:
        """
        Returns True if the user is marked as a super administrator.
        """

        user = self._get_user(user_id)

        return user.is_superuser

    def has_role(
        self,
        user_id: str,
        role_name: str,
    ) -> bool:
        """
        Returns True if the user has the specified role.
        """

        if self.is_super_admin(user_id):
            return True

        return (
            self.get_user_role(user_id).lower()
            == role_name.lower()
        )

    def has_any_role(
        self,
        user_id: str,
        roles: list[str] | set[str] | tuple[str, ...],
    ) -> bool:
        """
        Returns True if the user has at least one
        of the supplied roles.
        """

        if self.is_super_admin(user_id):
            return True

        current_role = self.get_user_role(user_id).lower()

        return current_role in {
            role.lower()
            for role in roles
        }

    def has_permission(
        self,
        user_id: str,
        permission: str,
    ) -> bool:
        """
        Returns True if the user owns the permission.
        """

        if self.is_super_admin(user_id):
            return True

        permissions = self.get_user_permissions(user_id)

        return permission in permissions

    def has_permissions(
        self,
        user_id: str,
        permissions: list[str] | set[str] | tuple[str, ...],
    ) -> bool:
        """
        Returns True only if the user owns every permission.
        """

        if self.is_super_admin(user_id):
            return True

        owned = self.get_user_permissions(user_id)

        return all(
            permission in owned
            for permission in permissions
        )

    def authorize(
        self,
        user_id: str,
        *,
        role: str | None = None,
        permission: str | None = None,
        permissions: list[str] | None = None,
    ) -> bool:
        """
        Enterprise authorization entry point.

        Examples
        --------
        authorize(user_id, role="admin")

        authorize(
            user_id,
            permission="documents.read",
        )

        authorize(
            user_id,
            permissions=[
                "documents.read",
                "documents.write",
            ],
        )
        """

        if self.is_super_admin(user_id):
            return True

        if role is not None:
            if not self.has_role(user_id, role):
                raise PermissionError(
                    f"Role '{role}' is required."
                )

        if permission is not None:
            if not self.has_permission(
                user_id,
                permission,
            ):
                raise PermissionError(
                    f"Permission '{permission}' is required."
                )

        if permissions is not None:
            if not self.has_permissions(
                user_id,
                permissions,
            ):
                raise PermissionError(
                    "One or more required permissions are missing."
                )

        return True


