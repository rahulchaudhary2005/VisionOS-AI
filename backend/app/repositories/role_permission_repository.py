from __future__ import annotations

from sqlalchemy import and_, delete, select
from sqlalchemy.orm import Session, joinedload

from app.models.role_permission import RolePermission
from app.repositories.base_repository import BaseRepository


class RolePermissionRepository(BaseRepository):
    """
    Repository responsible for Role-Permission relationship persistence.

    This repository manages the association between roles and permissions.
    Authorization decisions must remain inside AuthorizationService.
    """

    def __init__(self, db: Session) -> None:
        super().__init__(db)

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def create(
        self,
        mapping: RolePermission,
    ) -> RolePermission:
        """
        Persist a new role-permission mapping.
        """

        self.db.add(mapping)
        self.db.commit()
        self.db.refresh(mapping)

        return mapping

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_by_id(
        self,
        mapping_id: str,
    ) -> RolePermission | None:
        """
        Retrieve a mapping by primary key.
        """

        return self.db.get(RolePermission, mapping_id)

    def get(
        self,
        role_id: str,
        permission_id: str,
    ) -> RolePermission | None:
        """
        Retrieve a mapping using role and permission ids.
        """

        statement = (
            select(RolePermission)
            .where(
                and_(
                    RolePermission.role_id == role_id,
                    RolePermission.permission_id == permission_id,
                )
            )
        )

        return self.db.scalar(statement)

    def exists(
        self,
        role_id: int,
        permission_id: int,
    ) -> bool:
        """
        Check whether a role already owns a permission.
        """

        return self.get(role_id, permission_id) is not None

    def list_permissions_for_role(
        self,
        role_id: int,
    ) -> list[RolePermission]:
        """
        Return every permission assigned to a role.
        """

        statement = (
            select(RolePermission)
            .options(
                joinedload(RolePermission.permission)
            )
            .where(
                RolePermission.role_id == role_id
            )
        )

        return list(self.db.scalars(statement).unique().all())

    def list_roles_for_permission(
        self,
        permission_id: int,
    ) -> list[RolePermission]:
        """
        Return every role containing the supplied permission.
        """

        statement = (
            select(RolePermission)
            .options(
                joinedload(RolePermission.role)
            )
            .where(
                RolePermission.permission_id == permission_id
            )
        )

        return list(self.db.scalars(statement).unique().all())

    def list_all(self) -> list[RolePermission]:
        """
        Return every mapping with eager-loaded relations.
        """

        statement = (
            select(RolePermission)
            .options(
                joinedload(RolePermission.role),
                joinedload(RolePermission.permission),
            )
        )

        return list(self.db.scalars(statement).unique().all())

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    def save(
        self,
        mapping: RolePermission,
    ) -> RolePermission:
        """
        Persist modifications to an existing mapping.
        """

        self.db.add(mapping)
        self.db.commit()
        self.db.refresh(mapping)

        return mapping

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def delete(
        self,
        mapping: RolePermission,
    ) -> None:
        """
        Delete a role-permission mapping.
        """

        self.db.delete(mapping)
        self.db.commit()

    def remove_permission_from_role(
        self,
        role_id: int,
        permission_id: int,
    ) -> None:
        """
        Remove a permission from a role.
        """

        statement = (
            delete(RolePermission)
            .where(
                and_(
                    RolePermission.role_id == role_id,
                    RolePermission.permission_id == permission_id,
                )
            )
        )

        self.db.execute(statement)
        self.db.commit()

    def remove_all_permissions(
        self,
        role_id: int,
    ) -> None:
        """
        Remove every permission associated with a role.
        """

        statement = (
            delete(RolePermission)
            .where(
                RolePermission.role_id == role_id
            )
        )

        self.db.execute(statement)
        self.db.commit()

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def count(self) -> int:
        """
        Return total role-permission mappings.
        """

        statement = select(RolePermission)

        return len(self.db.scalars(statement).all())
