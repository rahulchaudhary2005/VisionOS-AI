"""
===============================================================================
VisionOS AI - Password Security Manager
===============================================================================

Production-grade password utilities for authentication and authorization.

This module provides a single cohesive PasswordManager responsible for:
- Password hashing
- Password verification
- Password policy validation
- Password strength checking
- Secure comparison helpers
- Future algorithm migration compatibility

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

import hashlib
import hmac
import logging
import re
import secrets
import string
from dataclasses import dataclass
from typing import Final, Optional

from app.config.settings import settings
from app.security.constants import (
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
    PASSWORD_REQUIRE_DIGIT,
    PASSWORD_REQUIRE_LOWERCASE,
    PASSWORD_REQUIRE_SPECIAL,
    PASSWORD_REQUIRE_UPPERCASE,
)
from app.security.exceptions import (
    AuthenticationServiceException,
    WeakPasswordException,
)
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError

logger = logging.getLogger(__name__)

DEFAULT_TIME_COST: Final[int] = 3
DEFAULT_MEMORY_COST: Final[int] = 65536
DEFAULT_PARALLELISM: Final[int] = 4
DEFAULT_HASH_LENGTH: Final[int] = 32
DEFAULT_SALT_LENGTH: Final[int] = 16


@dataclass(frozen=True, slots=True)
class PasswordPolicyResult:
    """
    Result of password policy validation.

    Attributes
    ----------
    is_valid:
        Indicates whether the password satisfies policy requirements.
    reasons:
        Human-readable list of violated rules.
    """

    is_valid: bool
    reasons: tuple[str, ...]


class PasswordManager:
    """
    Production password manager for VisionOS AI.

    This class centralizes all password lifecycle operations:
    - password hashing
    - password verification
    - password policy validation
    - password generation helpers
    - secure string comparison
    - future algorithm migration support
    """

    def __init__(
        self,
        time_cost: Optional[int] = None,
        memory_cost: Optional[int] = None,
        parallelism: Optional[int] = None,
        hash_length: Optional[int] = None,
        salt_length: Optional[int] = None,
    ) -> None:
        """
        Initialize the password manager.

        Parameters
        ----------
        time_cost:
            Argon2 time cost.
        memory_cost:
            Argon2 memory cost in kibibytes.
        parallelism:
            Argon2 parallelism.
        hash_length:
            Argon2 output hash length.
        salt_length:
            Argon2 salt length.
        """
        self._time_cost: int = int(
            time_cost
            or self._get_setting_value("PASSWORD_TIME_COST", default=DEFAULT_TIME_COST)
        )
        self._memory_cost: int = int(
            memory_cost
            or self._get_setting_value(
                "PASSWORD_MEMORY_COST", default=DEFAULT_MEMORY_COST
            )
        )
        self._parallelism: int = int(
            parallelism
            or self._get_setting_value(
                "PASSWORD_PARALLELISM", default=DEFAULT_PARALLELISM
            )
        )
        self._hash_length: int = int(
            hash_length
            or self._get_setting_value(
                "PASSWORD_HASH_LENGTH", default=DEFAULT_HASH_LENGTH
            )
        )
        self._salt_length: int = int(
            salt_length
            or self._get_setting_value(
                "PASSWORD_SALT_LENGTH", default=DEFAULT_SALT_LENGTH
            )
        )

        self._hasher = PasswordHasher(
            time_cost=self._time_cost,
            memory_cost=self._memory_cost,
            parallelism=self._parallelism,
            hash_len=self._hash_length,
            salt_len=self._salt_length,
        )

        self._validate_configuration()
        logger.debug(
            "PasswordManager initialized with time_cost=%s memory_cost=%s parallelism=%s",
            self._time_cost,
            self._memory_cost,
            self._parallelism,
        )

    def hash_password(self, password: str) -> str:
        """
        Hash a plaintext password using Argon2.

        Parameters
        ----------
        password:
            Plaintext password.

        Returns
        -------
        str
            Encoded password hash.
        """
        self.validate_password_policy(password)
        try:
            hashed = self._hasher.hash(password)
            logger.debug("Password hashed successfully")
            return hashed
        except Exception as exc:
            logger.exception("Password hashing failed")
            raise AuthenticationServiceException() from exc

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a plaintext password against a stored hash.

        Parameters
        ----------
        plain_password:
            User-provided plaintext password.
        hashed_password:
            Stored Argon2 password hash.

        Returns
        -------
        bool
            True when the password matches.
        """
        try:
            return self._hasher.verify(hashed_password, plain_password)
        except VerifyMismatchError:
            return False
        except (InvalidHash, VerificationError) as exc:
            logger.info("Password verification failed due to invalid hash: %s", exc)
            raise AuthenticationServiceException() from exc
        except Exception as exc:
            logger.exception("Unexpected password verification failure")
            raise AuthenticationServiceException() from exc

    def needs_rehash(self, hashed_password: str) -> bool:
        """
        Check whether an existing hash should be upgraded.

        Parameters
        ----------
        hashed_password:
            Stored hash.

        Returns
        -------
        bool
            True if rehash is recommended.
        """
        try:
            return self._hasher.check_needs_rehash(hashed_password)
        except Exception as exc:
            logger.info("Rehash check failed: %s", exc)
            raise AuthenticationServiceException() from exc

    def validate_password_policy(self, password: str) -> None:
        """
        Validate a password against the application's policy.

        Parameters
        ----------
        password:
            Candidate plaintext password.

        Raises
        ------
        WeakPasswordException
            If the password violates policy.
        """
        result = self.check_password_policy(password)
        if not result.is_valid:
            raise WeakPasswordException("; ".join(result.reasons))

    def check_password_policy(self, password: str) -> PasswordPolicyResult:
        """
        Evaluate a password against the policy without raising.

        Parameters
        ----------
        password:
            Candidate plaintext password.

        Returns
        -------
        PasswordPolicyResult
            Validation result and reasons.
        """
        reasons: list[str] = []

        if not isinstance(password, str):
            reasons.append("Password must be a string.")
            return PasswordPolicyResult(is_valid=False, reasons=tuple(reasons))

        if len(password) < PASSWORD_MIN_LENGTH:
            reasons.append(
                f"Password must be at least {PASSWORD_MIN_LENGTH} characters long."
            )

        if len(password) > PASSWORD_MAX_LENGTH:
            reasons.append(
                f"Password must be at most {PASSWORD_MAX_LENGTH} characters long."
            )

        if PASSWORD_REQUIRE_UPPERCASE and not re.search(r"[A-Z]", password):
            reasons.append("Password must contain at least one uppercase letter.")

        if PASSWORD_REQUIRE_LOWERCASE and not re.search(r"[a-z]", password):
            reasons.append("Password must contain at least one lowercase letter.")

        if PASSWORD_REQUIRE_DIGIT and not re.search(r"\d", password):
            reasons.append("Password must contain at least one digit.")

        if PASSWORD_REQUIRE_SPECIAL and not re.search(
            rf"[{re.escape(string.punctuation)}]", password
        ):
            reasons.append("Password must contain at least one special character.")

        return PasswordPolicyResult(
            is_valid=not reasons,
            reasons=tuple(reasons),
        )

    def generate_password(
        self,
        length: int = 16,
        include_uppercase: bool = True,
        include_lowercase: bool = True,
        include_digits: bool = True,
        include_special: bool = True,
    ) -> str:
        """
        Generate a strong random password.

        Parameters
        ----------
        length:
            Desired password length.
        include_uppercase:
            Include uppercase letters.
        include_lowercase:
            Include lowercase letters.
        include_digits:
            Include digits.
        include_special:
            Include special characters.

        Returns
        -------
        str
            Secure random password.
        """
        if length < PASSWORD_MIN_LENGTH:
            length = PASSWORD_MIN_LENGTH
        if length > PASSWORD_MAX_LENGTH:
            length = PASSWORD_MAX_LENGTH

        charset = ""
        pools: list[str] = []

        if include_uppercase:
            pools.append(string.ascii_uppercase)
        if include_lowercase:
            pools.append(string.ascii_lowercase)
        if include_digits:
            pools.append(string.digits)
        if include_special:
            pools.append(string.punctuation)

        if not pools:
            pools = [string.ascii_letters + string.digits]

        charset = "".join(pools)
        password_chars = [secrets.choice(pool) for pool in pools]

        while len(password_chars) < length:
            password_chars.append(secrets.choice(charset))

        secrets.SystemRandom().shuffle(password_chars)
        return "".join(password_chars[:length])

    def secure_compare(self, a: str, b: str) -> bool:
        """
        Perform a constant-time comparison of two strings.

        Parameters
        ----------
        a:
            First value.
        b:
            Second value.

        Returns
        -------
        bool
            True when both values match.
        """
        return hmac.compare_digest(a, b)

    def fingerprint_password(self, password: str) -> str:
        """
        Create a stable fingerprint for internal non-reversible tracking.

        This is not a password hash and must never be used for authentication.
        """
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def _validate_configuration(self) -> None:
        if self._time_cost <= 0:
            raise AuthenticationServiceException()
        if self._memory_cost <= 0:
            raise AuthenticationServiceException()
        if self._parallelism <= 0:
            raise AuthenticationServiceException()
        if self._hash_length <= 0:
            raise AuthenticationServiceException()
        if self._salt_length <= 0:
            raise AuthenticationServiceException()

    def _get_setting_value(self, name: str, default: int) -> int:
        if hasattr(settings, name):
            value = getattr(settings, name)
            if value is not None:
                return int(value)
        return default


__all__ = ["PasswordManager", "PasswordPolicyResult"]
