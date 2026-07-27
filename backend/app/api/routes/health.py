from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health():
    return {
        "status": "healthy",
        "project": "VisionOS AI",
        "version": "1.0.0",
    }