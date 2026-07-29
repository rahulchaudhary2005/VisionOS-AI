from __future__ import annotations

from app.schemas.base import BaseSchema
from pydantic import EmailStr, Field


class RegisterRequest(BaseSchema):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str | None = None


class UserProfileResponse(BaseSchema):
    id: str
    email: EmailStr
    full_name: str | None = None
    role: str
    is_active: bool
    is_verified: bool
    is_superuser: bool


class RegisterResponse(BaseSchema):
    success: bool = True
    message: str = "User registered successfully."
    user_id: str
