"""
===============================================================================
VisionOS AI - Security Types
===============================================================================

Enterprise Security Type Definitions

This module contains strongly typed models used by the authentication
and authorization subsystem.

Features
--------
✓ JWT Payload Models
✓ Access & Refresh Tokens
✓ Authentication Context
✓ Session Metadata
✓ Login Response
✓ Authorization Context
✓ Password Reset Models
✓ Future OAuth Compatibility

These models eliminate magic dictionaries and provide full IDE support.

Author: VisionOS AI
Architecture: Enterprise
===============================================================================
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.security.constants import UserRole


# =============================================================================
# Base Model
# =============================================================================

class SecurityBaseModel(BaseModel):
    """
    Base class for all security models.

    Provides:
    - Validation
    - Serialization
    - ORM compatibility
    """

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        extra="ignore",
        frozen=False,
    )


# =============================================================================
# JWT Payload
# =============================================================================

class JWTPayload(SecurityBaseModel):
    """
    JWT payload after decoding.

    This model represents the authenticated identity.
    """

    sub: UUID = Field(
        description="Unique user identifier"
    )

    email: EmailStr

    role: UserRole

    token_type: str

    jti: UUID

    iss: str

    aud: str

    iat: int

    exp: int

    nbf: Optional[int] = None


# =============================================================================
# Token Pair
# =============================================================================

class TokenPair(SecurityBaseModel):
    """
    Returned after successful login.
    """

    access_token: str

    refresh_token: str

    token_type: str = "Bearer"

    expires_in: int


# =============================================================================
# Access Token
# =============================================================================

class AccessToken(SecurityBaseModel):
    """
    Access token response.
    """

    access_token: str

    token_type: str = "Bearer"

    expires_in: int


# =============================================================================
# Refresh Token
# =============================================================================

class RefreshToken(SecurityBaseModel):
    """
    Refresh token model.
    """

    refresh_token: str


# =============================================================================
# Refresh Request
# =============================================================================

class RefreshRequest(SecurityBaseModel):
    """
    Request body for refreshing tokens.
    """

    refresh_token: str


# =============================================================================
# Login Request
# =============================================================================

class LoginRequest(SecurityBaseModel):
    """
    User login payload.
    """

    email: EmailStr

    password: str = Field(
        min_length=8,
        max_length=128,
    )


# =============================================================================
# Authentication Response
# =============================================================================

class AuthenticationResponse(SecurityBaseModel):
    """
    Response after successful authentication.
    """

    success: bool = True

    message: str = "Authentication successful."

    tokens: TokenPair


# =============================================================================
# Session Metadata
# =============================================================================

class SessionMetadata(SecurityBaseModel):
    """
    Session information.

    Stored later for audit logging.
    """

    session_id: UUID

    user_id: UUID

    ip_address: Optional[str] = None

    user_agent: Optional[str] = None

    created_at: datetime

    expires_at: datetime

    last_activity: datetime


# =============================================================================
# Authenticated User Context
# =============================================================================

class AuthenticatedUser(SecurityBaseModel):
    """
    Current authenticated user.

    Injected by FastAPI dependencies.
    """

    id: UUID

    email: EmailStr

    full_name: str

    role: UserRole

    is_active: bool

    is_verified: bool

    is_superuser: bool


# =============================================================================
# Authorization Context
# =============================================================================

class AuthorizationContext(SecurityBaseModel):
    """
    Complete authorization context.

    Available to RBAC middleware.
    """

    user: AuthenticatedUser

    permissions: list[str] = Field(default_factory=list)

    scopes: list[str] = Field(default_factory=list)

    session: Optional[SessionMetadata] = None


# =============================================================================
# Password Reset
# =============================================================================

class PasswordResetRequest(SecurityBaseModel):
    """
    Request password reset.
    """

    email: EmailStr


class PasswordResetConfirm(SecurityBaseModel):
    """
    Confirm password reset.
    """

    token: str

    new_password: str = Field(
        min_length=8,
        max_length=128,
    )


# =============================================================================
# Email Verification
# =============================================================================

class EmailVerification(SecurityBaseModel):
    """
    Email verification payload.
    """

    token: str


# =============================================================================
# API Key Authentication (Future AI Services)
# =============================================================================

class APIKeyContext(SecurityBaseModel):
    """
    Used by future AI microservices.
    """

    key_id: UUID

    owner: str

    permissions: list[str]

    expires_at: Optional[datetime] = None


# =============================================================================
# OAuth Identity (Future)
# =============================================================================

class OAuthIdentity(SecurityBaseModel):
    """
    Future Google/GitHub login support.
    """

    provider: str

    provider_user_id: str

    email: EmailStr

    full_name: Optional[str] = None

    avatar_url: Optional[str] = None


# =============================================================================
# Audit Event
# =============================================================================

class SecurityAuditEvent(SecurityBaseModel):
    """
    Security event for audit logs.
    """

    event: str

    user_id: Optional[UUID] = None

    ip_address: Optional[str] = None

    success: bool = True

    timestamp: datetime

    details: dict = Field(default_factory=dict)