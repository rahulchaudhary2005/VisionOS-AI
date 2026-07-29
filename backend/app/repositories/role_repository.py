from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.role import Role
from app.repositories.base_repository import BaseRepository


class RoleRepository(BaseRepository):
    """
    Repository responsible for Role persistence operations.

    This repository provides optimized database access for role entities.
    Business rules and RBAC evaluation belong to the AuthorizationService.
    """

    def __init__(self, db: Session) -> None:
        super().__init__(db)

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def create(self, role: Role) -> Role:
        """
        Persist a new role.
        """

        self.db.add(role)
        self.db.commit()
        self.db.refresh(role)

        return role

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_by_id(
        self,
        role_id: str,
    ) -> Role | None:
        """
        Retrieve a role by its primary key.
        """

        return self.db.get(Role, role_id)

    def get_by_name(
        self,
        name: str,
    ) -> Role | None:
        """
        Retrieve a role using its unique name.
        """

        statement = (
            select(Role)
            .where(Role.name == name.strip().lower())
        )

        return self.db.scalar(statement)

    def list_all(self) -> list[Role]:
        """
        Return all available roles ordered alphabetically.
        """

        statement = (
            select(Role)
            .order_by(Role.name.asc())
        )

        return list(self.db.scalars(statement).all())

    def exists(
        self,
        name: str,
    ) -> bool:
        """
        Determine whether a role exists.
        """

        return self.get_by_name(name) is not None

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    def save(
        self,
        role: Role,
    ) -> Role:
        """
        Persist modifications to an existing role.
        """

        self.db.add(role)
        self.db.commit()
        self.db.refresh(role)

        return role

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def delete(
        self,
        role: Role,
    ) -> None:
        """
        Delete a role from persistence.
        """

        self.db.delete(role)
        self.db.commit()

    # ------------------------------------------------------------------
    # Query Helpers
    # ------------------------------------------------------------------

    def search(
        self,
        keyword: str,
    ) -> list[Role]:
        """
        Search roles using a partial role name.
        """

        statement = (
            select(Role)
            .where(Role.name.ilike(f"%{keyword.strip()}%"))
            .order_by(Role.name.asc())
        )

        return list(self.db.scalars(statement).all())

    def count(self) -> int:
        """
        Return total number of stored roles.
        """

        statement = select(Role)

        return len(self.db.scalars(statement).all())
