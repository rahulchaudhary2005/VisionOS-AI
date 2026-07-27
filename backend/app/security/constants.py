"""
===============================================================================
VisionOS AI - Security Constants
===============================================================================

This module contains all authentication and authorization constants used
throughout the application.

Centralizing these values prevents magic strings, improves maintainability,
and ensures consistency across the authentication subsystem.

Author: VisionOS AI
Architecture: Enterprise
===============================================================================
"""

from enum import Enum
from typing import Final


# =============================================================================
# JWT Configuration
# =============================================================================

JWT_ALGORITHM: Final[str] = "HS256"

ACCESS_TOKEN_TYPE: Final[str] = "access"
REFRESH_TOKEN_TYPE: Final[str] = "refresh"

BEARER_SCHEME: Final[str] = "Bearer"


# =============================================================================
# JWT Claims
# =============================================================================

CLAIM_SUBJECT: Final[str] = "sub"

CLAIM_EMAIL: Final[str] = "email"

CLAIM_ROLE: Final[str] = "role"

CLAIM_TOKEN_TYPE: Final[str] = "token_type"

CLAIM_ISSUED_AT: Final[str] = "iat"

CLAIM_EXPIRES: Final[str] = "exp"

CLAIM_NOT_BEFORE: Final[str] = "nbf"

CLAIM_ISSUER: Final[str] = "iss"

CLAIM_AUDIENCE: Final[str] = "aud"

CLAIM_JWT_ID: Final[str] = "jti"


# =============================================================================
# User Roles
# =============================================================================

class UserRole(str, Enum):
    """
    System roles.

    More roles can be added later without modifying the security logic.
    """

    ADMIN = "admin"

    MODERATOR = "moderator"

    USER = "user"

    AI_ENGINE = "ai_engine"

    SERVICE = "service"


# =============================================================================
# User Status
# =============================================================================

class UserStatus(str, Enum):
    """
    Current account status.
    """

    ACTIVE = "active"

    INACTIVE = "inactive"

    PENDING = "pending"

    SUSPENDED = "suspended"

    LOCKED = "locked"

    DELETED = "deleted"


# =============================================================================
# Permissions
# =============================================================================

class Permission(str, Enum):
    """
    Permission identifiers.

    RBAC middleware will use these.
    """

    READ = "read"

    WRITE = "write"

    UPDATE = "update"

    DELETE = "delete"

    MANAGE_USERS = "manage_users"

    MANAGE_ROLES = "manage_roles"

    MANAGE_AI = "manage_ai"

    MANAGE_SYSTEM = "manage_system"

    VIEW_AUDIT_LOGS = "view_audit_logs"

    TRAIN_MODELS = "train_models"


# =============================================================================
# Authentication Events
# =============================================================================

LOGIN_SUCCESS: Final[str] = "login_success"

LOGIN_FAILED: Final[str] = "login_failed"

LOGOUT: Final[str] = "logout"

TOKEN_REFRESH: Final[str] = "token_refresh"

PASSWORD_CHANGED: Final[str] = "password_changed"

ACCOUNT_LOCKED: Final[str] = "account_locked"


# =============================================================================
# Default Limits
# =============================================================================

MAX_LOGIN_ATTEMPTS: Final[int] = 5

ACCOUNT_LOCK_MINUTES: Final[int] = 30

PASSWORD_MIN_LENGTH: Final[int] = 8

PASSWORD_MAX_LENGTH: Final[int] = 128


# =============================================================================
# Password Rules
# =============================================================================

PASSWORD_REQUIRE_UPPERCASE: Final[bool] = True

PASSWORD_REQUIRE_LOWERCASE: Final[bool] = True

PASSWORD_REQUIRE_DIGIT: Final[bool] = True

PASSWORD_REQUIRE_SPECIAL: Final[bool] = True


# =============================================================================
# API Headers
# =============================================================================

HEADER_AUTHORIZATION: Final[str] = "Authorization"

HEADER_REQUEST_ID: Final[str] = "X-Request-ID"

HEADER_PROCESS_TIME: Final[str] = "X-Process-Time"


# =============================================================================
# OAuth2
# =============================================================================

TOKEN_URL: Final[str] = "/api/v1/auth/login"

AUTH_SCHEME_NAME: Final[str] = "JWT Authentication"


# =============================================================================
# Future AI Authentication
# =============================================================================

AI_SERVICE_NAME: Final[str] = "VisionOS AI"

AI_API_AUDIENCE: Final[str] = "visionos-ai"

TOKEN_ISSUER: Final[str] = "visionos-auth"