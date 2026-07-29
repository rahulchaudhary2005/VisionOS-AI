"""
===============================================================================
VisionOS AI - Security Exceptions
===============================================================================

Enterprise Authentication & Authorization Exception Hierarchy

This module centralizes all security-related exceptions.

Features:
- Standardized HTTP responses
- Error codes
- Security logging compatibility
- Future localization support
- Clean authentication flow

Author: VisionOS AI
Architecture: Enterprise
===============================================================================
"""

from typing import Optional

from fastapi import HTTPException, status

# =============================================================================
# Base Security Exception
# =============================================================================


class SecurityException(HTTPException):
    """
    Base class for every security-related exception.

    Parameters
    ----------
    status_code : int
        HTTP status code.

    detail : str
        Human-readable error message.

    error_code : str
        Internal machine-readable error identifier.
    """

    def __init__(
        self,
        status_code: int,
        detail: str,
        error_code: str,
        headers: Optional[dict] = None,
    ):
        super().__init__(
            status_code=status_code,
            detail={
                "success": False,
                "error": {
                    "code": error_code,
                    "message": detail,
                },
            },
            headers=headers,
        )


# =============================================================================
# Authentication Exceptions
# =============================================================================


class InvalidCredentialsException(SecurityException):
    """Raised when username/email or password is incorrect."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            error_code="INVALID_CREDENTIALS",
            headers={"WWW-Authenticate": "Bearer"},
        )


class InvalidTokenException(SecurityException):
    """Raised when JWT is malformed or invalid."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
            error_code="INVALID_TOKEN",
            headers={"WWW-Authenticate": "Bearer"},
        )


class ExpiredTokenException(SecurityException):
    """Raised when JWT has expired."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired.",
            error_code="TOKEN_EXPIRED",
            headers={"WWW-Authenticate": "Bearer"},
        )


class MissingTokenException(SecurityException):
    """Raised when Authorization header is missing."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is missing.",
            error_code="TOKEN_MISSING",
            headers={"WWW-Authenticate": "Bearer"},
        )


class InvalidTokenTypeException(SecurityException):
    """Raised when refresh token is used as access token."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type.",
            error_code="INVALID_TOKEN_TYPE",
            headers={"WWW-Authenticate": "Bearer"},
        )


# =============================================================================
# Authorization Exceptions
# =============================================================================


class PermissionDeniedException(SecurityException):
    """Raised when user lacks permission."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to perform this action.",
            error_code="PERMISSION_DENIED",
        )


class RoleRequiredException(SecurityException):
    """Raised when required role is missing."""

    def __init__(self, role: str):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{role}' is required.",
            error_code="ROLE_REQUIRED",
        )


# =============================================================================
# User Exceptions
# =============================================================================


class UserNotFoundException(SecurityException):
    """Raised when user cannot be found."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
            error_code="USER_NOT_FOUND",
        )


class UserAlreadyExistsException(SecurityException):
    """Raised when attempting to register an existing user."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists.",
            error_code="USER_ALREADY_EXISTS",
        )


class UserInactiveException(SecurityException):
    """Raised when inactive account attempts login."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive.",
            error_code="USER_INACTIVE",
        )


class UserLockedException(SecurityException):
    """Raised when account has been locked."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_423_LOCKED,
            detail="User account is locked.",
            error_code="USER_LOCKED",
        )


class UserSuspendedException(SecurityException):
    """Raised when account is suspended."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account has been suspended.",
            error_code="USER_SUSPENDED",
        )


# =============================================================================
# Password Exceptions
# =============================================================================


class WeakPasswordException(SecurityException):
    """Raised when password policy validation fails."""

    def __init__(self, reason: str):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=reason,
            error_code="WEAK_PASSWORD",
        )


class PasswordMismatchException(SecurityException):
    """Raised when password confirmation fails."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match.",
            error_code="PASSWORD_MISMATCH",
        )


# =============================================================================
# Account Security Exceptions
# =============================================================================


class TooManyLoginAttemptsException(SecurityException):
    """Raised after exceeding maximum login attempts."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later.",
            error_code="TOO_MANY_LOGIN_ATTEMPTS",
        )


class RefreshTokenRevokedException(SecurityException):
    """Raised when refresh token has been revoked."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked.",
            error_code="REFRESH_TOKEN_REVOKED",
            headers={"WWW-Authenticate": "Bearer"},
        )


class SessionExpiredException(SecurityException):
    """Raised when user session has expired."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please login again.",
            error_code="SESSION_EXPIRED",
            headers={"WWW-Authenticate": "Bearer"},
        )


# =============================================================================
# Internal Security Exceptions
# =============================================================================


class AuthenticationServiceException(SecurityException):
    """
    Raised for unexpected authentication service failures.
    """

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service is temporarily unavailable.",
            error_code="AUTH_SERVICE_ERROR",
        )


class AuthorizationServiceException(SecurityException):
    """
    Raised for unexpected authorization service failures.
    """

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authorization service is temporarily unavailable.",
            error_code="AUTHORIZATION_SERVICE_ERROR",
        )
# =============================================================================
# Role Exceptions
# =============================================================================

class RoleNotFoundException(SecurityException):
    """Raised when a role cannot be found."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found.",
            error_code="ROLE_NOT_FOUND",
        )


class RoleAlreadyExistsException(SecurityException):
    """Raised when attempting to create a duplicate role."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail="Role already exists.",
            error_code="ROLE_ALREADY_EXISTS",
        )


class SystemRoleModificationException(SecurityException):
    """Raised when a protected system role cannot be modified."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="System roles cannot be modified.",
            error_code="SYSTEM_ROLE_PROTECTED",
        )


# =============================================================================
# Permission Exceptions
# =============================================================================

class PermissionNotFoundException(SecurityException):
    """Raised when a permission cannot be found."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found.",
            error_code="PERMISSION_NOT_FOUND",
        )


class PermissionAlreadyExistsException(SecurityException):
    """Raised when attempting to create a duplicate permission."""

    def __init__(self):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail="Permission already exists.",
            error_code="PERMISSION_ALREADY_EXISTS",
        )
