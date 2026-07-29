"""
===============================================================================
VisionOS AI - User Service
===============================================================================

Enterprise User Service

Responsibilities
----------------
* User lifecycle management
* User profile operations
* User role management
* Password management
* Account activation/deactivation
* User search
* User administration

Author: VisionOS AI
Architecture: Enterprise
===============================================================================
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.auth.authorization_service import AuthorizationService
from app.models.role import Role
from app.models.user import User
from app.repositories.role_repository import RoleRepository
from app.repositories.user_repository import UserRepository
from app.security.constants import UserStatus
from app.security.exceptions import (
    AuthenticationServiceException,
    UserAlreadyExistsException,
    UserNotFoundException,
)
from app.security.password import PasswordManager
from app.services.base_service import BaseService

logger = logging.getLogger(__name__)


class UserService(BaseService):
    """
    Enterprise User Service.

    Coordinates all user-related business logic.

    Responsibilities
    ----------------
    * User CRUD
    * Password management
    * Role assignment
    * Profile management
    * Account status management
    """

    # ------------------------------------------------------------------
    # Constructor
    # ------------------------------------------------------------------

    def __init__(
        self,
        db: Session,
        password_manager: PasswordManager | None = None,
    ) -> None:
        super().__init__(db)

        self.user_repository = UserRepository(db)

        self.role_repository = RoleRepository(db)

        self.password_manager = (
            password_manager
            or PasswordManager()
        )

        self.authorization_service = (
            AuthorizationService(db)
        )

    # ------------------------------------------------------------------
    # Private Helpers
    # ------------------------------------------------------------------

    def _get_user(
        self,
        user_id: str,
    ) -> User:
        """
        Retrieve a user by ID.

        Raises
        ------
        UserNotFoundException
        """

        user = self.user_repository.get_by_id(user_id)

        if user is None:
            raise UserNotFoundException()

        return user

    def _get_role(
        self,
        role_name: str,
    ) -> Role:
        """
        Retrieve a role by name.

        Raises
        ------
        AuthenticationServiceException
        """

        role = self.role_repository.get_by_name(
            role_name.strip().lower()
        )

        if role is None:
            raise AuthenticationServiceException(
                f"Role '{role_name}' does not exist."
            )

        return role

    def _normalize_email(
        self,
        email: str,
    ) -> str:
        """
        Normalize an email address.
        """

        return email.strip().lower()

    def _hash_password(
        self,
        password: str,
    ) -> str:
        """
        Hash a plaintext password.
        """

        return self.password_manager.hash_password(
            password
        )

    def _verify_password(
        self,
        plain_password: str,
        hashed_password: str,
    ) -> bool:
        """
        Verify a password.
        """

        return self.password_manager.verify_password(
            plain_password,
            hashed_password,
        )

    def _email_exists(
        self,
        email: str,
    ) -> bool:
        """
        Returns True if the email already exists.
        """

        return self.user_repository.exists_by_email(
            self._normalize_email(email)
        )

    def _validate_unique_email(
        self,
        email: str,
    ) -> None:
        """
        Ensure an email address is unique.
        """

        if self._email_exists(email):
            raise UserAlreadyExistsException()

    def _validate_status(
        self,
        user: User,
    ) -> None:
        """
        Validate that a user account is usable.
        """

        if user.status == UserStatus.LOCKED:
            raise AuthenticationServiceException(
                "User account is locked."
            )

        if user.status == UserStatus.SUSPENDED:
            raise AuthenticationServiceException(
                "User account is suspended."
            )

        if user.status == UserStatus.INACTIVE:
            raise AuthenticationServiceException(
                "User account is inactive."
            )

    def _save(
        self,
        user: User,
    ) -> User:
        """
        Persist user changes.
        """

        return self.user_repository.save(user)

        # ------------------------------------------------------------------
    # User Creation
    # ------------------------------------------------------------------

    def create_user(
        self,
        *,
        email: str,
        password: str,
        full_name: str | None = None,
        role_name: str = "user",
        is_superuser: bool = False,
        is_verified: bool = True,
        status: UserStatus = UserStatus.ACTIVE,
    ) -> User:
        """
        Create a new user.

        Raises
        ------
        UserAlreadyExistsException
        AuthenticationServiceException
        """

        normalized_email = self._normalize_email(email)

        self._validate_unique_email(normalized_email)

        role = self._get_role(role_name)

        user = User(
            email=normalized_email,
            full_name=full_name,
            hashed_password=self._hash_password(password),
            role_id=role.id,
            status=status,
            is_superuser=is_superuser,
            is_verified=is_verified,
        )

        created_user = self.user_repository.create(user)

        logger.info(
            "User created successfully (id=%s)",
            created_user.id,
        )

        return created_user

    # ------------------------------------------------------------------
    # User Retrieval
    # ------------------------------------------------------------------

    def get_user_by_id(
        self,
        user_id: str,
    ) -> User:
        """
        Retrieve a user by ID.
        """

        return self._get_user(user_id)

    def get_user_by_email(
        self,
        email: str,
    ) -> User:
        """
        Retrieve a user by email.

        Raises
        ------
        UserNotFoundException
        """

        normalized_email = self._normalize_email(email)

        user = self.user_repository.get_by_email(
            normalized_email,
        )

        if user is None:
            raise UserNotFoundException()

        return user

    # ------------------------------------------------------------------
    # User Listing
    # ------------------------------------------------------------------

    def list_users(self) -> list[User]:
        """
        Return every user.

        Repository should return users ordered by
        creation date or email.
        """

        return self.user_repository.list_all()

    def search_users(
        self,
        keyword: str,
    ) -> list[User]:
        """
        Search users.

        Delegates to repository.
        """

        keyword = keyword.strip()

        if not keyword:
            return self.list_users()

        return self.user_repository.search(keyword)

    # ------------------------------------------------------------------
    # Profile Management
    # ------------------------------------------------------------------

    def update_profile(
        self,
        user_id: str,
        *,
        full_name: str | None = None,
    ) -> User:
        """
        Update user profile.
        """

        user = self._get_user(user_id)

        if full_name is not None:
            user.full_name = full_name.strip()

        updated = self._save(user)

        logger.info(
            "Profile updated (id=%s)",
            updated.id,
        )

        return updated

    def update_email(
        self,
        user_id: str,
        new_email: str,
    ) -> User:
        """
        Update a user's email address.
        """

        user = self._get_user(user_id)

        normalized_email = self._normalize_email(
            new_email,
        )

        existing = self.user_repository.get_by_email(
            normalized_email,
        )

        if (
            existing is not None
            and existing.id != user.id
        ):
            raise UserAlreadyExistsException()

        user.email = normalized_email

        updated = self._save(user)

        logger.info(
            "Email updated (id=%s)",
            updated.id,
        )

        return updated

    # ------------------------------------------------------------------
    # Information Helpers
    # ------------------------------------------------------------------

    def user_exists(
        self,
        email: str,
    ) -> bool:
        """
        Returns True if the email is already registered.
        """

        return self._email_exists(email)

    def count_users(self) -> int:
        """
        Return total number of users.
        """

        return self.user_repository.count()

        # ------------------------------------------------------------------
    # Password Management
    # ------------------------------------------------------------------

    def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
    ) -> User:
        """
        Change a user's password.

        Raises
        ------
        UserNotFoundException
        InvalidCredentialsException
        """

        from app.security.exceptions import InvalidCredentialsException

        user = self._get_user(user_id)

        if not self._verify_password(
            current_password,
            user.hashed_password,
        ):
            raise InvalidCredentialsException()

        user.hashed_password = self._hash_password(
            new_password,
        )

        updated = self._save(user)

        logger.info(
            "Password updated (id=%s)",
            updated.id,
        )

        return updated

    def reset_password(
        self,
        user_id: str,
        new_password: str,
    ) -> User:
        """
        Administrative password reset.
        """

        user = self._get_user(user_id)

        user.hashed_password = self._hash_password(
            new_password,
        )

        updated = self._save(user)

        logger.info(
            "Password reset (id=%s)",
            updated.id,
        )

        return updated

    # ------------------------------------------------------------------
    # Role Management
    # ------------------------------------------------------------------

    def assign_role(
        self,
        user_id: str,
        role_name: str,
    ) -> User:
        """
        Assign a new role to a user.
        """

        user = self._get_user(user_id)

        role = self._get_role(role_name)

        user.role_id = role.id

        updated = self._save(user)

        self.authorization_service.refresh_role(
            user.id,
        )

        self.authorization_service.refresh_user_permissions(
            user.id,
        )

        logger.info(
            "Role '%s' assigned to user=%s",
            role.name,
            updated.id,
        )

        return updated

    def get_user_role(
        self,
        user_id: str,
    ) -> str:
        """
        Return the current role name.
        """

        return self.authorization_service.get_user_role(
            user_id,
        )

    def get_user_permissions(
        self,
        user_id: str,
    ) -> set[str]:
        """
        Return all permissions assigned to a user.
        """

        return self.authorization_service.get_user_permissions(
            user_id,
        )

    # ------------------------------------------------------------------
    # Account Status Management
    # ------------------------------------------------------------------

    def activate_user(
        self,
        user_id: str,
    ) -> User:
        """
        Activate a user account.
        """

        user = self._get_user(user_id)

        user.activate()

        updated = self._save(user)

        logger.info(
            "User activated (id=%s)",
            updated.id,
        )

        return updated

    def deactivate_user(
        self,
        user_id: str,
    ) -> User:
        """
        Deactivate a user account.
        """

        user = self._get_user(user_id)

        user.deactivate()

        updated = self._save(user)

        logger.info(
            "User deactivated (id=%s)",
            updated.id,
        )

        return updated

    def suspend_user(
        self,
        user_id: str,
    ) -> User:
        """
        Suspend a user account.
        """

        user = self._get_user(user_id)

        user.suspend()

        updated = self._save(user)

        logger.info(
            "User suspended (id=%s)",
            updated.id,
        )

        return updated

    def lock_user(
        self,
        user_id: str,
    ) -> User:
        """
        Lock a user account.
        """

        user = self._get_user(user_id)

        user.lock()

        updated = self._save(user)

        logger.info(
            "User locked (id=%s)",
            updated.id,
        )

        return updated

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_user(
        self,
        user_id: str,
    ) -> User:
        """
        Mark a user as verified.
        """

        user = self._get_user(user_id)

        user.is_verified = True

        updated = self._save(user)

        logger.info(
            "User verified (id=%s)",
            updated.id,
        )

        return updated

    # ------------------------------------------------------------------
    # Deletion
    # ------------------------------------------------------------------

    def delete_user(
        self,
        user_id: str,
    ) -> None:
        """
        Permanently delete a user.

        NOTE:
        Requires UserRepository.delete().
        """

        user = self._get_user(user_id)

        self.user_repository.delete(user)

        logger.info(
            "User deleted (id=%s)",
            user.id,
        )

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def is_superuser(
        self,
        user_id: str,
    ) -> bool:
        """
        Returns whether the user is a superuser.
        """

        return self._get_user(
            user_id,
        ).is_superuser

    def is_active(
        self,
        user_id: str,
    ) -> bool:
        """
        Returns whether the user account is active.
        """

        return self._get_user(
            user_id,
        ).is_active()

    def refresh_authorization_cache(
        self,
        user_id: str,
    ) -> None:
        """
        Refresh cached RBAC data.
        """

        self.authorization_service.refresh_role(
            user_id,
        )

        self.authorization_service.refresh_user_permissions(
            user_id,
        )
