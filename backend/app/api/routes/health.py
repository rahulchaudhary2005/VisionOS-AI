from fastapi import APIRouter

from app.schemas.health import HealthResponse

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Application Health Check",
)
async def health_check() -> HealthResponse:
    """
    Returns the health status of the application.
    """

    return HealthResponse(
        success=True,
        project="VisionOS AI",
        version="1.0.0",
        status="healthy",
    )