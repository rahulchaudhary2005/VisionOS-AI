from datetime import datetime

from pydantic import BaseModel, ConfigDict


class BaseSchema(BaseModel):
    """
    Base schema for all API models.

    Every response/request model in the project should inherit from this class.
    """

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
        populate_by_name=True,
        validate_assignment=True,
    )


class TimestampSchema(BaseSchema):
    """
    Adds timestamp support to derived schemas.
    """

    created_at: datetime | None = None
    updated_at: datetime | None = None
