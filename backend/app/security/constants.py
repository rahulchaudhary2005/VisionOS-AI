"""
===============================================================================
VisionOS AI - Enterprise Security Constants
===============================================================================

Centralized security constants used across the VisionOS AI platform.

This module intentionally contains only generic security constants and enums.

Role and Permission registries live in:

    app.auth.roles
    app.auth.permissions

to avoid duplication and circular dependencies.
===============================================================================
"""

from __future__ import annotations

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
# HTTP Headers
# =============================================================================

HEADER_AUTHORIZATION: Final[str] = "Authorization"

HEADER_REQUEST_ID: Final[str] = "X-Request-ID"

HEADER_PROCESS_TIME: Final[str] = "X-Process-Time"

HEADER_CORRELATION_ID: Final[str] = "X-Correlation-ID"

HEADER_USER_AGENT: Final[str] = "User-Agent"

HEADER_FORWARDED_FOR: Final[str] = "X-Forwarded-For"

HEADER_REAL_IP: Final[str] = "X-Real-IP"


# =============================================================================
# OAuth
# =============================================================================

TOKEN_URL: Final[str] = "/api/v1/auth/login"

AUTH_SCHEME_NAME: Final[str] = "JWT Authentication"

TOKEN_ISSUER: Final[str] = "visionos-auth"

AI_API_AUDIENCE: Final[str] = "visionos-ai"

AI_SERVICE_NAME: Final[str] = "VisionOS AI"


# =============================================================================
# Token Types
# =============================================================================

class TokenType(str, Enum):
    """
    Supported JWT token types.
    """

    ACCESS = "access"

    REFRESH = "refresh"

    API_KEY = "api_key"

    SERVICE = "service"

    RESET_PASSWORD = "reset_password"

    EMAIL_VERIFICATION = "email_verification"


# =============================================================================
# User Status
# =============================================================================

class UserStatus(str, Enum):
    """
    Current lifecycle state of a user account.
    """

    ACTIVE = "active"

    INACTIVE = "inactive"

    PENDING = "pending"

    SUSPENDED = "suspended"

    LOCKED = "locked"

    DELETED = "deleted"


# =============================================================================
# Authentication Method
# =============================================================================

class AuthenticationMethod(str, Enum):
    """
    Authentication mechanism used by the client.
    """

    PASSWORD = "password"

    OAUTH = "oauth"

    API_KEY = "api_key"

    FACE_RECOGNITION = "face_recognition"

    VOICE = "voice"

    SERVICE_ACCOUNT = "service_account"


# =============================================================================
# OAuth Providers
# =============================================================================

class OAuthProvider(str, Enum):
    """
    Supported OAuth providers.
    """

    GOOGLE = "google"

    GITHUB = "github"

    MICROSOFT = "microsoft"

    APPLE = "apple"

    LOCAL = "local"


# =============================================================================
# Multi-Factor Authentication
# =============================================================================

class MFAType(str, Enum):
    """
    Supported MFA methods.
    """

    NONE = "none"

    TOTP = "totp"

    EMAIL = "email"

    SMS = "sms"

    FACE = "face"

    HARDWARE_KEY = "hardware_key"


# =============================================================================
# Exported Symbols
# =============================================================================

__all__ = [
    "JWT_ALGORITHM",
    "ACCESS_TOKEN_TYPE",
    "REFRESH_TOKEN_TYPE",
    "BEARER_SCHEME",
    "CLAIM_SUBJECT",
    "CLAIM_EMAIL",
    "CLAIM_ROLE",
    "CLAIM_TOKEN_TYPE",
    "CLAIM_ISSUED_AT",
    "CLAIM_EXPIRES",
    "CLAIM_NOT_BEFORE",
    "CLAIM_ISSUER",
    "CLAIM_AUDIENCE",
    "CLAIM_JWT_ID",
    "HEADER_AUTHORIZATION",
    "HEADER_REQUEST_ID",
    "HEADER_PROCESS_TIME",
    "HEADER_CORRELATION_ID",
    "HEADER_USER_AGENT",
    "HEADER_FORWARDED_FOR",
    "HEADER_REAL_IP",
    "TOKEN_URL",
    "AUTH_SCHEME_NAME",
    "TOKEN_ISSUER",
    "AI_API_AUDIENCE",
    "AI_SERVICE_NAME",
    "TokenType",
    "UserStatus",
    "AuthenticationMethod",
    "OAuthProvider",
    "MFAType",
]
