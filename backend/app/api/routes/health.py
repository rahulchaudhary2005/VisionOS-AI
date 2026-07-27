from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.schemas.health import HealthResponse
from app.services.health_service import HealthService

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Application Health Check",
)
async def health_check(
    db: Session = Depends(get_db),
) -> HealthResponse:
    """
    Returns the current health status of the application.
    """

    service = HealthService(db)

    return service.get_health()