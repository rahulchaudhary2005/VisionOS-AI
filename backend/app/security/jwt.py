"""
===============================================================================
VisionOS AI - JWT Security Manager
===============================================================================

Production-grade JWT utilities for authentication and authorization.

This module provides a single, cohesive JWTManager responsible for:
- Access token creation
- Refresh token creation
- Token decoding and validation
- Claim normalization and enforcement
- Future blacklist compatibility
- Future key rotation compatibility

Architecture goals:
- Typed, explicit, and framework-friendly
- Secure defaults
- FastAPI integration ready
- Enterprise logging and exception handling
- Compatible with app.security.constants, app.security.types, and
  app.security.exceptions

Author: VisionOS AI
Architecture: Enterprise
===============================================================================
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Mapping, Optional
from uuid import UUID, uuid4

from app.config.settings import settings
from app.security.constants import (
    ACCESS_TOKEN_TYPE,
    AI_API_AUDIENCE,
    CLAIM_AUDIENCE,
    CLAIM_EMAIL,
    CLAIM_EXPIRES,
    CLAIM_ISSUED_AT,
    CLAIM_ISSUER,
    CLAIM_JWT_ID,
    CLAIM_NOT_BEFORE,
    CLAIM_ROLE,
    CLAIM_SUBJECT,
    CLAIM_TOKEN_TYPE,
    JWT_ALGORITHM,
    REFRESH_TOKEN_TYPE,
    TOKEN_ISSUER,
    UserRole,
)
from app.security.exceptions import (
    AuthenticationServiceException,
    ExpiredTokenException,
    InvalidTokenException,
    InvalidTokenTypeException,
)
from app.security.types import JWTPayload
from jose import ExpiredSignatureError, JWTError, jwt
from pydantic import EmailStr, TypeAdapter, ValidationError

logger = logging.getLogger(__name__)

EmailAdapter: Final[TypeAdapter[EmailStr]] = TypeAdapter(EmailStr)
UUIDAdapter: Final[TypeAdapter[UUID]] = TypeAdapter(UUID)
#RoleAdapter: Final[TypeAdapter[UserRole]] = TypeAdapter(UserRole)


@dataclass(frozen=True, slots=True)
class TokenSpec:
    """
    Immutable token specification.

    Attributes
    ----------
    token_type:
        Logical JWT token type claim.
    expires_delta:
        Lifetime of the token.
    audience:
        Intended token audience.
    """

    token_type: str
    expires_delta: timedelta
    audience: str


class JWTManager:
    """
    Production JWT manager for VisionOS AI.

    This class centralizes all token lifecycle operations:
    - issuing access tokens
    - issuing refresh tokens
    - decoding and validating JWTs
    - enforcing claim integrity
    - preparing for blacklist and key rotation support
    """

    _SUPPORTED_CLOCK_SKEW_SECONDS: Final[int] = 30

    def __init__(
        self,
        secret_key: Optional[str] = None,
        algorithm: str = JWT_ALGORITHM,
        issuer: str = TOKEN_ISSUER,
        audience: str = AI_API_AUDIENCE,
        access_token_minutes: Optional[int] = None,
        refresh_token_days: Optional[int] = None,
    ) -> None:
        """
        Initialize the JWT manager.

        Parameters
        ----------
        secret_key:
            Signing secret. Falls back to application settings.
        algorithm:
            JWT algorithm. Defaults to HS256.
        issuer:
            Expected issuer claim.
        audience:
            Expected audience claim.
        access_token_minutes:
            Access token lifetime in minutes.
        refresh_token_days:
            Refresh token lifetime in days.
        """
        self._secret_key: str = secret_key or self._get_setting_value(
            "JWT_SECRET_KEY",
            "SECRET_KEY",
            "secret_key",
        )
        self._algorithm: str = algorithm
        self._issuer: str = issuer
        self._audience: str = audience
        self._access_token_minutes: int = int(
            access_token_minutes
            if access_token_minutes is not None
            else self._get_setting_value(
                "ACCESS_TOKEN_EXPIRE_MINUTES",
                "JWT_ACCESS_TOKEN_EXPIRE_MINUTES",
                default=15,
            )
        )
        self._refresh_token_days: int = int(
            refresh_token_days
            if refresh_token_days is not None
            else self._get_setting_value(
                "REFRESH_TOKEN_EXPIRE_DAYS",
                "JWT_REFRESH_TOKEN_EXPIRE_DAYS",
                default=30,
            )
        )
        self._blacklist_lookup_enabled: bool = False
        self._key_rotation_enabled: bool = True

        self._validate_configuration()
        logger.debug(
            "JWTManager initialized with issuer=%s audience=%s algorithm=%s",
            self._issuer,
            self._audience,
            self._algorithm,
        )

    @property
    def algorithm(self) -> str:
        """Return the signing algorithm."""
        return self._algorithm

    @property
    def issuer(self) -> str:
        """Return the configured issuer."""
        return self._issuer

    @property
    def audience(self) -> str:
        """Return the configured audience."""
        return self._audience

    @property
    def access_token_minutes(self) -> int:
        """Return access token lifetime in minutes."""
        return self._access_token_minutes

    @property
    def refresh_token_days(self) -> int:
        """Return refresh token lifetime in days."""
        return self._refresh_token_days

    def create_access_token(
        self,
        subject: UUID | str,
        email: str | EmailStr,
        role: UserRole | str,
        custom_claims: Optional[Mapping[str, Any]] = None,
        expires_delta: Optional[timedelta] = None,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        not_before: Optional[datetime] = None,
        jti: Optional[UUID] = None,
    ) -> str:
        """
        Create a signed access token.

        Parameters
        ----------
        subject:
            UUID subject identifier.
        email:
            User email address.
        role:
            User role.
        custom_claims:
            Extra claims to merge into the JWT payload.
        expires_delta:
            Optional explicit lifetime override.
        issuer:
            Optional issuer override.
        audience:
            Optional audience override.
        not_before:
            Optional not-before timestamp.
        jti:
            Optional JWT ID override.

        Returns
        -------
        str
            Encoded JWT access token.
        """
        spec = TokenSpec(
            token_type=ACCESS_TOKEN_TYPE,
            expires_delta=(
                expires_delta
                if expires_delta is not None
                else timedelta(minutes=self._access_token_minutes)
            ),
            audience=audience or self._audience,
        )
        payload = self._build_payload(
            subject=subject,
            email=email,
            role=role,
            token_spec=spec,
            issuer=issuer or self._issuer,
            not_before=not_before,
            jti=jti,
            custom_claims=custom_claims,
        )
        token = self._encode(payload)
        logger.debug("Created access token for subject=%s", payload[CLAIM_SUBJECT])
        return token

    def create_refresh_token(
        self,
        subject: UUID | str,
        email: str | EmailStr,
        role:  str,
        custom_claims: Optional[Mapping[str, Any]] = None,
        expires_delta: Optional[timedelta] = None,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        not_before: Optional[datetime] = None,
        jti: Optional[UUID] = None,
    ) -> str:
        """
        Create a signed refresh token.

        Parameters
        ----------
        subject:
            UUID subject identifier.
        email:
            User email address.
        role:
            User role.
        custom_claims:
            Extra claims to merge into the JWT payload.
        expires_delta:
            Optional explicit lifetime override.
        issuer:
            Optional issuer override.
        audience:
            Optional audience override.
        not_before:
            Optional not-before timestamp.
        jti:
            Optional JWT ID override.

        Returns
        -------
        str
            Encoded JWT refresh token.
        """
        spec = TokenSpec(
            token_type=REFRESH_TOKEN_TYPE,
            expires_delta=(
                expires_delta
                if expires_delta is not None
                else timedelta(days=self._refresh_token_days)
            ),
            audience=audience or self._audience,
        )
        payload = self._build_payload(
            subject=subject,
            email=email,
            role=role,
            token_spec=spec,
            issuer=issuer or self._issuer,
            not_before=not_before,
            jti=jti,
            custom_claims=custom_claims,
        )
        token = self._encode(payload)
        logger.debug("Created refresh token for subject=%s", payload[CLAIM_SUBJECT])
        return token

    def decode_token(
        self,
        token: str,
        expected_token_type: Optional[str] = None,
        verify_expiration: bool = True,
        verify_issuer: bool = True,
        verify_audience: bool = True,
    ) -> JWTPayload:
        """
        Decode and validate a JWT.

        Parameters
        ----------
        token:
            Encoded JWT string.
        expected_token_type:
            Optional type enforcement, e.g. access or refresh.
        verify_expiration:
            Enforce expiration validation.
        verify_issuer:
            Enforce issuer validation.
        verify_audience:
            Enforce audience validation.

        Returns
        -------
        JWTPayload
            Validated JWT payload model.

        Raises
        ------
        InvalidTokenException
            If token is malformed or invalid.
        ExpiredTokenException
            If token is expired.
        InvalidTokenTypeException
            If token type is unexpected.
        """
        try:
            options = self._build_decode_options(
                verify_expiration=verify_expiration,
                verify_issuer=verify_issuer,
                verify_audience=verify_audience,
            )
            # python-jose's `jwt.decode` does not accept a `leeway` kwarg.
            # Move clock-skew tolerance into our expiration validation.
            decoded = jwt.decode(
                token,
                self._secret_key,
                algorithms=[self._algorithm],
                issuer=self._issuer if verify_issuer else None,
                audience=self._audience if verify_audience else None,
                options=options,
            )
            payload = self._parse_payload(decoded)
            self._validate_payload(payload)
            if expected_token_type is not None:
                self.validate_token_type(payload, expected_token_type)
            return payload
        except ExpiredSignatureError as exc:
            logger.info("Expired token rejected: %s", exc)
            raise ExpiredTokenException() from exc
        except ValidationError as exc:
            logger.info("JWT payload validation failed: %s", exc)
            raise InvalidTokenException() from exc
        except JWTError as exc:
            logger.info("JWT decode failed: %s", exc)
            raise InvalidTokenException() from exc
        except Exception as exc:
            logger.exception("Unexpected JWT decoding failure")
            raise AuthenticationServiceException() from exc

    def validate_token(
        self,
        token: str,
        expected_token_type: Optional[str] = None,
    ) -> JWTPayload:
        """
        Validate a token end-to-end and return its payload.

        This is the preferred public API for authentication workflows.

        Parameters
        ----------
        token:
            Encoded JWT string.
        expected_token_type:
            Optional token type to enforce.

        Returns
        -------
        JWTPayload
            Validated payload.
        """
        payload = self.decode_token(
            token=token,
            expected_token_type=expected_token_type,
            verify_expiration=True,
            verify_issuer=True,
            verify_audience=True,
        )
        self.validate_expiration(payload)
        self.validate_issuer(payload)
        self.validate_audience(payload)
        if expected_token_type is not None:
            self.validate_token_type(payload, expected_token_type)
        self._validate_not_blacklisted(payload)
        return payload

    def validate_token_type(
        self,
        payload: JWTPayload | Mapping[str, Any],
        expected_token_type: str,
    ) -> None:
        """
        Ensure the payload token type matches expectations.

        Parameters
        ----------
        payload:
            JWT payload or mapping.
        expected_token_type:
            Expected token type string.
        """
        token_type = self._get_claim(payload, CLAIM_TOKEN_TYPE)
        if token_type != expected_token_type:
            logger.info(
                "Token type validation failed: expected=%s actual=%s",
                expected_token_type,
                token_type,
            )
            raise InvalidTokenTypeException()

    def validate_expiration(self, payload: JWTPayload | Mapping[str, Any]) -> None:
        """
        Validate expiration and not-before timestamps.

        Parameters
        ----------
        payload:
            JWT payload or mapping.
        """
        now = self._now()
        exp = self._get_int_claim(payload, CLAIM_EXPIRES)
        # Allow a small clock skew (leeway) when validating expiration so
        # tokens issued from slightly skewed clocks don't fail validation.
        if (now.timestamp() - self._SUPPORTED_CLOCK_SKEW_SECONDS) >= exp:
            raise ExpiredTokenException()

        nbf = self._get_optional_int_claim(payload, CLAIM_NOT_BEFORE)
        if nbf is not None and now.timestamp() < nbf:
            raise InvalidTokenException()

    def validate_issuer(self, payload: JWTPayload | Mapping[str, Any]) -> None:
        """
        Validate the issuer claim.

        Parameters
        ----------
        payload:
            JWT payload or mapping.
        """
        issuer = self._get_claim(payload, CLAIM_ISSUER)
        if issuer != self._issuer:
            logger.info(
                "Issuer validation failed: expected=%s actual=%s", self._issuer, issuer
            )
            raise InvalidTokenException()

    def validate_audience(self, payload: JWTPayload | Mapping[str, Any]) -> None:
        """
        Validate the audience claim.

        Parameters
        ----------
        payload:
            JWT payload or mapping.
        """
        audience = self._get_claim(payload, CLAIM_AUDIENCE)
        if audience != self._audience:
            logger.info(
                "Audience validation failed: expected=%s actual=%s",
                self._audience,
                audience,
            )
            raise InvalidTokenException()

    def generate_jti(self) -> UUID:
        """
        Generate a cryptographically strong JWT ID.

        Returns
        -------
        UUID
            New unique token identifier.
        """
        return uuid4()

    def is_blacklisted(self, jti: UUID | str) -> bool:
        """
        Placeholder-compatible blacklist check.

        Future implementations can connect this to Redis, database storage,
        or a distributed revocation service.

        Parameters
        ----------
        jti:
            JWT ID to check.

        Returns
        -------
        bool
            Always False in the current implementation.
        """
        if not self._blacklist_lookup_enabled:
            return False
        return False

    def revoke_token(self, jti: UUID | str) -> None:
        """
        Future blacklist compatibility hook.

        This method intentionally performs no persistence yet, but provides a
        stable integration point for token revocation systems.
        """
        logger.debug("Token revocation requested for jti=%s", jti)

    def verify_claims(
        self,
        payload: JWTPayload | Mapping[str, Any],
    ) -> JWTPayload:
        """
        Validate payload shape and claims.

        Parameters
        ----------
        payload:
            JWT payload or raw mapping.

        Returns
        -------
        JWTPayload
            Normalized payload model.
        """
        if isinstance(payload, JWTPayload):
            self._validate_payload(payload)
            return payload
        normalized = self._parse_payload(dict(payload))
        self._validate_payload(normalized)
        return normalized

    def decode_without_validation(self, token: str) -> Mapping[str, Any]:
        """
        Decode a token without enforcing semantic validation.

        This helper is useful for debugging and controlled internal flows.
        It still verifies the signature.
        """
        try:
            return jwt.decode(
                token,
                self._secret_key,
                algorithms=[self._algorithm],
                options={
                    "verify_signature": True,
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "verify_aud": False,
                    "verify_iss": False,
                },
            )
        except JWTError as exc:
            raise InvalidTokenException() from exc

    def _build_payload(
        self,
        subject: UUID | str,
        email: str | EmailStr,
        role:  str,
        token_spec: TokenSpec,
        issuer: str,
        not_before: Optional[datetime],
        jti: Optional[UUID],
        custom_claims: Optional[Mapping[str, Any]],
    ) -> dict[str, Any]:
        now = self._now()
        subject_uuid = self._normalize_uuid(subject, field_name=CLAIM_SUBJECT)
        email_value = self._normalize_email(email)
        role_value = self._normalize_role(role)
        token_jti = jti or self.generate_jti()
        nbf_dt = not_before or now

        payload: dict[str, Any] = {
            CLAIM_SUBJECT: str(subject_uuid),
            CLAIM_EMAIL: email_value,
            CLAIM_ROLE: role_value,
            CLAIM_TOKEN_TYPE: token_spec.token_type,
            CLAIM_JWT_ID: str(token_jti),
            CLAIM_ISSUER: issuer,
            CLAIM_AUDIENCE: token_spec.audience,
            CLAIM_ISSUED_AT: int(now.timestamp()),
            CLAIM_EXPIRES: int((now + token_spec.expires_delta).timestamp()),
            CLAIM_NOT_BEFORE: int(nbf_dt.timestamp()),
        }

        if custom_claims:
            payload.update(dict(custom_claims))

        payload[CLAIM_SUBJECT] = str(subject_uuid)
        payload[CLAIM_EMAIL] = email_value
        payload[CLAIM_ROLE] = role_value
        payload[CLAIM_TOKEN_TYPE] = token_spec.token_type
        payload[CLAIM_JWT_ID] = str(token_jti)
        payload[CLAIM_ISSUER] = issuer
        payload[CLAIM_AUDIENCE] = token_spec.audience
        payload[CLAIM_ISSUED_AT] = int(now.timestamp())
        payload[CLAIM_EXPIRES] = int((now + token_spec.expires_delta).timestamp())
        payload[CLAIM_NOT_BEFORE] = int(nbf_dt.timestamp())

        return payload

    def _encode(self, payload: Mapping[str, Any]) -> str:
        try:
            return jwt.encode(
                claims=dict(payload),
                key=self._secret_key,
                algorithm=self._algorithm,
            )
        except JWTError as exc:
            logger.exception("JWT encoding failed")
            raise AuthenticationServiceException() from exc
        except Exception as exc:
            logger.exception("Unexpected JWT encoding failure")
            raise AuthenticationServiceException() from exc

    def _parse_payload(self, decoded: Mapping[str, Any]) -> JWTPayload:
        try:
            return JWTPayload.model_validate(decoded)
        except ValidationError as exc:
            logger.info("Decoded payload did not match JWTPayload: %s", exc)
            raise InvalidTokenException() from exc

    def _validate_payload(self, payload: JWTPayload) -> None:
        self._validate_not_blacklisted(payload)
        if payload.iss != self._issuer:
            raise InvalidTokenException()
        if payload.aud != self._audience:
            raise InvalidTokenException()
        if payload.token_type not in {ACCESS_TOKEN_TYPE, REFRESH_TOKEN_TYPE}:
            raise InvalidTokenException()

    def _validate_not_blacklisted(self, payload: JWTPayload) -> None:
        if self.is_blacklisted(payload.jti):
            raise InvalidTokenException()

    def _build_decode_options(
        self,
        verify_expiration: bool,
        verify_issuer: bool,
        verify_audience: bool,
    ) -> dict[str, bool]:
        return {
            "verify_signature": True,
            "verify_exp": verify_expiration,
            "verify_nbf": True,
            "verify_iat": True,
            "verify_aud": verify_audience,
            "verify_iss": verify_issuer,
        }

    def _get_claim(
        self,
        payload: JWTPayload | Mapping[str, Any],
        claim_name: str,
    ) -> Any:
        if isinstance(payload, JWTPayload):
            return getattr(payload, claim_name)
        return payload[claim_name]

    def _get_int_claim(
        self,
        payload: JWTPayload | Mapping[str, Any],
        claim_name: str,
    ) -> int:
        value = self._get_claim(payload, claim_name)
        return int(value)

    def _get_optional_int_claim(
        self,
        payload: JWTPayload | Mapping[str, Any],
        claim_name: str,
    ) -> Optional[int]:
        if isinstance(payload, JWTPayload):
            value = getattr(payload, claim_name)
        else:
            value = payload.get(claim_name)
        if value is None:
            return None
        return int(value)

    def _normalize_uuid(self, value: UUID | str, field_name: str) -> UUID:
        try:
            return UUIDAdapter.validate_python(value)
        except ValidationError as exc:
            logger.info("Invalid UUID for %s: %s", field_name, exc)
            raise InvalidTokenException() from exc

    def _normalize_email(self, value: str | EmailStr) -> str:
        try:
            normalized = EmailAdapter.validate_python(value)
            return str(normalized)
        except ValidationError as exc:
            logger.info("Invalid email claim: %s", exc)
            raise InvalidTokenException() from exc

    def _normalize_role(self, value: str) -> str:
      """
      Normalize the role stored in JWT.

      The JWT stores the database role name
      (for example "admin", "doctor", "researcher").
      """

      if not isinstance(value, str):
        raise InvalidTokenException()

      role = value.strip().lower()

      if not role:
        raise InvalidTokenException()

      return role

    def _validate_configuration(self) -> None:
        if not isinstance(self._secret_key, str) or not self._secret_key.strip():
            raise AuthenticationServiceException()
        if not isinstance(self._algorithm, str) or not self._algorithm.strip():
            raise AuthenticationServiceException()
        if not isinstance(self._issuer, str) or not self._issuer.strip():
            raise AuthenticationServiceException()
        if not isinstance(self._audience, str) or not self._audience.strip():
            raise AuthenticationServiceException()
        if self._access_token_minutes <= 0:
            raise AuthenticationServiceException()
        if self._refresh_token_days <= 0:
            raise AuthenticationServiceException()

    def _get_setting_value(
        self,
        *names: str,
        default: Any = None,
    ) -> Any:
        for name in names:
            if hasattr(settings, name):
                value = getattr(settings, name)
                if value is not None:
                    return value
        return default

    def _now(self) -> datetime:
        return datetime.now(UTC)


__all__ = ["JWTManager", "TokenSpec"]
