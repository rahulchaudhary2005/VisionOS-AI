from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.permission import Permission
from app.repositories.base_repository import BaseRepository


class PermissionRepository(BaseRepository):
    """
    Repository responsible for Permission persistence operations.

    This repository intentionally contains only database access logic.
    Business rules, authorization decisions, and RBAC validation belong
    to the AuthorizationService.
    """

    def __init__(self, db: Session) -> None:
        super().__init__(db)

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def create(self, permission: Permission) -> Permission:
        """
        Persist a new permission.
        """

        self.db.add(permission)
        self.db.commit()
        self.db.refresh(permission)

        return permission

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_by_id(
        self,
        permission_id: str,
    ) -> Permission | None:
        """
        Retrieve a permission by primary key.
        """

        return self.db.get(Permission, permission_id)

    def get_by_name(
        self,
        name: str,
    ) -> Permission | None:
        """
        Retrieve a permission by its unique name.
        """

        statement = (
            select(Permission)
            .where(Permission.name == name.strip().lower())
        )

        return self.db.scalar(statement)

    def list_all(self) -> list[Permission]:
        """
        Return every permission ordered alphabetically.
        """

        statement = (
            select(Permission)
            .order_by(Permission.name.asc())
        )

        return list(self.db.scalars(statement).all())

    def exists(
        self,
        name: str,
    ) -> bool:
        """
        Determine whether a permission already exists.
        """

        return self.get_by_name(name) is not None

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    def save(
        self,
        permission: Permission,
    ) -> Permission:
        """
        Persist changes to an existing permission.
        """

        self.db.add(permission)
        self.db.commit()
        self.db.refresh(permission)

        return permission

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def delete(
        self,
        permission: Permission,
    ) -> None:
        """
        Remove a permission from persistence.
        """

        self.db.delete(permission)
        self.db.commit()

    # ------------------------------------------------------------------
    # Query Helpers
    # ------------------------------------------------------------------

    def search(
        self,
        keyword: str,
    ) -> list[Permission]:
        """
        Search permissions by partial name.
        """

        statement = (
            select(Permission)
            .where(
                Permission.name.ilike(f"%{keyword.strip()}%")
            )
            .order_by(Permission.name.asc())
        )

        return list(self.db.scalars(statement).all())

    def count(self) -> int:
        """
        Return total permission count.
        """

        return len(self.list_all())
