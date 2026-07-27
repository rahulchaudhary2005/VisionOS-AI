from typing import Any

from app.schemas.base import BaseSchema


class APIResponse(BaseSchema):
    """
    Standard API response envelope.
    """

    success: bool = True
    message: str
    data: Any | None = None


class ErrorResponse(BaseSchema):
    """
    Standard error response.
    """

    success: bool = False
    message: str