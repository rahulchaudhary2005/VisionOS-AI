from app.api.dependencies.database import get_db
from app.auth.dependencies import get_current_user
from app.security.types import (
    AuthenticatedUser,
    AuthenticationResponse,
    LoginRequest,
    RefreshRequest,
)
from app.services.auth_service import AuthService
from fastapi import APIRouter, Depends

router = APIRouter()


@router.post(
    "/auth/login",
    response_model=AuthenticationResponse,
    summary="Authenticate a user and issue access and refresh tokens.",
)
async def login(
    credentials: LoginRequest,
    db=Depends(get_db),
) -> AuthenticationResponse:
    service = AuthService(db)
    tokens = service.authenticate(credentials.email, credentials.password)
    return AuthenticationResponse(tokens=tokens)


@router.post(
    "/auth/refresh",
    response_model=AuthenticationResponse,
    summary="Refresh access and refresh tokens using a valid refresh token.",
)
async def refresh(
    refresh_request: RefreshRequest,
    db=Depends(get_db),
) -> AuthenticationResponse:
    service = AuthService(db)
    tokens = service.refresh_tokens(refresh_request.refresh_token)
    return AuthenticationResponse(tokens=tokens)


@router.get(
    "/auth/me",
    response_model=AuthenticatedUser,
    summary="Return the authenticated user's profile.",
)
async def me(current_user=Depends(get_current_user)) -> AuthenticatedUser:
    return current_user
