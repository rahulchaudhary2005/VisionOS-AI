from app.api.dependencies.database import get_db
from app.schemas.auth import RegisterRequest, RegisterResponse
from app.services.user_service import UserService
from fastapi import APIRouter, Depends

router = APIRouter()


@router.post(
    "/auth/register",
    response_model=RegisterResponse,
    summary="Register a new user account.",
)
async def register(
    request: RegisterRequest,
    db=Depends(get_db),
) -> RegisterResponse:
    service = UserService(db)
    user = service.register_user(
        email=request.email,
        password=request.password,
        full_name=request.full_name,
    )

    return RegisterResponse(user_id=str(user.id))
