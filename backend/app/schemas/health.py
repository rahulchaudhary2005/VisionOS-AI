from app.schemas.base import BaseSchema


class HealthResponse(BaseSchema):
    """
    Health endpoint response.
    """

    success: bool
    project: str
    version: str
    status: str