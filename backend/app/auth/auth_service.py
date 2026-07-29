"""
===============================================================================
VisionOS AI - Authentication Service
===============================================================================

Enterprise Authentication Service

Responsibilities
----------------
- User authentication
- User registration
- Password verification
- Password hashing
- JWT generation
- Refresh token workflow
- Password changes
- Logout
- Email verification (future)
- Password reset (future)

Author: VisionOS AI
Architecture: Enterprise
===============================================================================
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session
from app.repositories.role_repository import RoleRepository
from app.auth.authorization_service import AuthorizationService
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.security.constants import (
    ACCESS_TOKEN_TYPE,
    REFRESH_TOKEN_TYPE,
    UserStatus,
)
from app.security.exceptions import (
    AuthenticationServiceException,
    InvalidCredentialsException,
    InvalidTokenException,
    UserAlreadyExistsException,
    UserInactiveException,
    UserLockedException,
    UserNotFoundException,
    UserSuspendedException,
)
from app.security.jwt import JWTManager
from app.security.password import PasswordManager
from app.security.types import (
    AuthenticationResponse,
    JWTPayload,
    TokenPair,
)

logger = logging.getLogger(__name__)


class AuthService:
    """
    Enterprise Authentication Service.

    Coordinates authentication between:

        UserRepository
              │
              ▼
        PasswordManager
              │
              ▼
          JWTManager
              │
              ▼
     AuthorizationService
    """

    def __init__(self, db: Session) -> None:
        """
        Initialize authentication service.

        Parameters
        ----------
        db:
            Active SQLAlchemy session.
        """

        self.db = db

        self.user_repository = UserRepository(db)

        self.role_repository = RoleRepository(db)

        self.password_manager = PasswordManager()

        self.jwt_manager = JWTManager()

        self.authorization_service = AuthorizationService(db)

    # ---------------------------------------------------------------------
    # Private Helpers
    # ---------------------------------------------------------------------

    def _get_user_by_email(self, email: str) -> User:
        """
        Retrieve a user by email.

        Raises
        ------
        UserNotFoundException
        """

        user = self.user_repository.get_by_email(email)

        if user is None:
            raise UserNotFoundException()

        return user

    def _verify_password(
        self,
        plain_password: str,
        hashed_password: str,
    ) -> bool:
        """
        Verify a plaintext password.
        """

        return self.password_manager.verify_password(
            plain_password,
            hashed_password,
        )

    def _hash_password(self, password: str) -> str:
        """
        Hash a plaintext password.
        """

        return self.password_manager.hash_password(password)

    def _validate_account_status(self, user: User) -> None:
        """
        Validate whether a user account is allowed to authenticate.
        """

        if user.status == UserStatus.PENDING:
            raise UserInactiveException()

        if user.status == UserStatus.INACTIVE:
            raise UserInactiveException()

        if user.status == UserStatus.LOCKED:
            raise UserLockedException()

        if user.status == UserStatus.SUSPENDED:
            raise UserSuspendedException()

    def _generate_token_pair(
        self,
        user: User,
    ) -> TokenPair:
        """
        Generate access and refresh tokens for a user.
        """

        access_token = self.jwt_manager.create_access_token(
            subject=user.id,
            email=user.email,
            role=user.role_name,
        )

        refresh_token = self.jwt_manager.create_refresh_token(
            subject=user.id,
            email=user.email,
            role=user.role_name,
        )

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="Bearer",
            expires_in=self.jwt_manager.access_token_minutes * 60,
        )

    def _authentication_response(
        self,
        tokens: TokenPair,
    ) -> AuthenticationResponse:
        """
        Build the standard authentication response.
        """

        return AuthenticationResponse(
            success=True,
            message="Authentication successful.",
            tokens=tokens,
        )

     # ---------------------------------------------------------------------
    # Authentication
    # ---------------------------------------------------------------------

    def authenticate(
        self,
        email: str,
        password: str,
    ) -> AuthenticationResponse:
        """
        Authenticate a user using email and password.

        Workflow
        --------
        1. Load user
        2. Validate account status
        3. Verify password
        4. Upgrade password hash if needed
        5. Generate JWT tokens
        6. Return authentication response

        Raises
        ------
        UserNotFoundException
        InvalidCredentialsException
        UserInactiveException
        UserLockedException
        UserSuspendedException
        AuthenticationServiceException
        """

        try:
            user = self._get_user_by_email(email)

            self._validate_account_status(user)

            if not self._verify_password(
                password,
                user.hashed_password,
            ):
                logger.warning(
                    "Authentication failed for email=%s (invalid password)",
                    email,
                )
                raise InvalidCredentialsException()

            if self.password_manager.needs_rehash(user.hashed_password):
                logger.info(
                    "Upgrading password hash for user=%s",
                    user.email,
                )

                user.hashed_password = self._hash_password(password)

                self.user_repository.save(user)

            tokens = self._generate_token_pair(user)

            logger.info(
                "User authenticated successfully: %s",
                user.email,
            )

            return self._authentication_response(tokens)

        except (
            UserNotFoundException,
            InvalidCredentialsException,
            UserInactiveException,
            UserLockedException,
            UserSuspendedException,
        ):
            raise

        except Exception as exc:
            logger.exception(
                "Unexpected authentication failure."
            )
            raise AuthenticationServiceException() from exc

    def login(
        self,
        email: str,
        password: str,
    ) -> AuthenticationResponse:
        """
        Login entry point.

        This is an alias around authenticate() so routers
        can expose either /login or /authenticate while
        sharing identical business logic.
        """

        return self.authenticate(
            email=email,
            password=password,
        )

    # ---------------------------------------------------------------------
    # Token Helpers
    # ---------------------------------------------------------------------

    def create_token_pair(
        self,
        user: User,
    ) -> TokenPair:
        """
        Public helper for generating JWT token pairs.

        Primarily used after registration,
        password reset,
        OAuth login,
        or refresh-token rotation.
        """

        return self._generate_token_pair(user)

    def create_authentication_response(
        self,
        user: User,
    ) -> AuthenticationResponse:
        """
        Create a complete authentication response for
        an already authenticated user.
        """

        tokens = self.create_token_pair(user)

        return self._authentication_response(tokens)
        # ---------------------------------------------------------------------
    # Registration
    # ---------------------------------------------------------------------

    def register_user(
        self,
        email: str,
        password: str,
        full_name: str | None = None,
        role_name: str = "user",
        auto_activate: bool = False,
        auto_login: bool = False,
    ) -> AuthenticationResponse | User:

        """
        Register a new VisionOS AI user.

        Workflow
        --------
        1. Validate duplicate email
        2. Retrieve requested role
        3. Validate password policy
        4. Hash password
        5. Create user
        6. Persist user
        7. Optionally activate account
        8. Optionally return authentication tokens

        Parameters
        ----------
        email:
            User email.

        password:
            Plaintext password.

        full_name:
            Optional display name.

        role_name:
            Initial role.
            Defaults to "user".

        auto_activate:
            Automatically activate account.

        auto_login:
            Return JWT tokens immediately after registration.

        Returns
        -------
        User
            Newly created user.

        AuthenticationResponse
            Returned only when auto_login=True.
        """

        try:

            # ---------------------------------------------------------
            # Duplicate email
            # ---------------------------------------------------------

            if self.user_repository.exists_by_email(email):
                raise UserAlreadyExistsException()

            # ---------------------------------------------------------
            # Default role
            # ---------------------------------------------------------

            # from app.repositories.role_repository import RoleRepository

            # role_repository = RoleRepository(self.db)

            role = self.role_repository.get_by_name(role_name)

            if role is None:
                raise AuthenticationServiceException()

            # ---------------------------------------------------------
            # Password hashing
            # ---------------------------------------------------------

            hashed_password = self._hash_password(password)

            # ---------------------------------------------------------
            # Create user
            # ---------------------------------------------------------

            user = User(
                email=email.lower().strip(),
                full_name=full_name,
                hashed_password=hashed_password,
                role_id=role.id,
                status=(
                    UserStatus.ACTIVE
                    if auto_activate
                    else UserStatus.PENDING
                ),
                is_verified=auto_activate,
                is_superuser=False,
            )

            created_user = self.user_repository.create(user)

            logger.info(
                "New user registered: %s",
                created_user.email,
            )

            # ---------------------------------------------------------
            # Optional auto-login
            # ---------------------------------------------------------

            if auto_login:

                tokens = self._generate_token_pair(created_user)

                return self._authentication_response(tokens)

            return created_user

        except (
            UserAlreadyExistsException,
        ):
            raise

        except Exception as exc:
            logger.exception(
                "Unexpected registration failure."
            )
            raise AuthenticationServiceException() from exc


    def email_exists(
           self,
           email: str,
           ) -> bool:
            """
            Determine whether an email address is already registered.
            """

            return self.user_repository.exists_by_email(email)

     # ---------------------------------------------------------------------
    # Token Management
    # ---------------------------------------------------------------------

    def refresh_tokens(
        self,
        refresh_token: str,
    ) -> AuthenticationResponse:
        """
        Refresh an expired access token using a valid refresh token.

        Workflow
        --------
        1. Validate refresh token
        2. Load user
        3. Validate account status
        4. Rotate access + refresh tokens
        5. Return authentication response
        """

        try:

            payload = self.jwt_manager.validate_token(
                token=refresh_token,
                expected_token_type=REFRESH_TOKEN_TYPE,
            )

            user = self.user_repository.get_by_id(
                str(payload.sub),
            )

            if user is None:
                raise UserNotFoundException()

            self._validate_account_status(user)

            tokens = self._generate_token_pair(user)

            logger.info(
                "Refresh token rotated for user=%s",
                user.email,
            )

            return self._authentication_response(tokens)

        except (
            InvalidTokenException,
            UserNotFoundException,
            UserInactiveException,
            UserLockedException,
            UserSuspendedException,
        ):
            raise

        except Exception as exc:
            logger.exception(
                "Unexpected refresh-token failure."
            )
            raise AuthenticationServiceException() from exc

    # ---------------------------------------------------------------------
    # Logout
    # ---------------------------------------------------------------------

    def logout(
        self,
        access_token: str,
    ) -> None:
        """
        Logout the current user.

        Future versions will blacklist the token.

        Current implementation validates the token
        and provides a stable extension point.
        """

        try:

            payload = self.jwt_manager.validate_token(
                token=access_token,
                expected_token_type=ACCESS_TOKEN_TYPE,
            )

            self.jwt_manager.revoke_token(
                payload.jti,
            )

            logger.info(
                "User logged out (jti=%s)",
                payload.jti,
            )

        except InvalidTokenException:
            raise

        except Exception as exc:
            logger.exception(
                "Logout failure."
            )
            raise AuthenticationServiceException() from exc

    # ---------------------------------------------------------------------
    # Password Management
    # ---------------------------------------------------------------------

    def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
    ) -> None:
        """
        Change a user's password.

        The current password must be verified
        before a new password is accepted.
        """

        try:

            user = self.user_repository.get_by_id(user_id)

            if user is None:
                raise UserNotFoundException()

            if not self._verify_password(
                current_password,
                user.hashed_password,
            ):
                raise InvalidCredentialsException()

            user.hashed_password = self._hash_password(
                new_password,
            )

            self.user_repository.save(user)

            logger.info(
                "Password changed for user=%s",
                user.email,
            )

        except (
            UserNotFoundException,
            InvalidCredentialsException,
        ):
            raise

        except Exception as exc:
            logger.exception(
                "Password change failed."
            )
            raise AuthenticationServiceException() from exc

    # ---------------------------------------------------------------------
    # Email Verification (Future)
    # ---------------------------------------------------------------------

    def verify_email(
        self,
        user_id: str,
    ) -> User:
        """
        Mark a user's email as verified.

        Future versions will verify signed
        email-verification tokens.
        """

        user = self.user_repository.get_by_id(user_id)

        if user is None:
            raise UserNotFoundException()

        user.activate()

        self.user_repository.save(user)

        logger.info(
            "User verified: %s",
            user.email,
        )

        return user

    # ---------------------------------------------------------------------
    # Utility Methods
    # ---------------------------------------------------------------------

    def get_user(
        self,
        user_id: str,
    ) -> User:
        """
        Retrieve a user by identifier.
        """

        user = self.user_repository.get_by_id(user_id)

        if user is None:
            raise UserNotFoundException()

        return user

    def validate_access_token(
        self,
        access_token: str,
    ) -> JWTPayload:
        """
        Validate an access token and return its payload.
        """

        return self.jwt_manager.validate_token(
            token=access_token,
            expected_token_type=ACCESS_TOKEN_TYPE,
        )

    def validate_refresh_token(
        self,
        refresh_token: str,
    ) -> JWTPayload:
        """
        Validate a refresh token and return its payload.
        """

        return self.jwt_manager.validate_token(
            token=refresh_token,
            expected_token_type=REFRESH_TOKEN_TYPE,
        )

__all__ = ["AuthService"]
