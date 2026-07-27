from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes.health import router as health_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Starting VisionOS AI Backend...")
    yield
    print("🛑 Shutting down VisionOS AI Backend...")


app = FastAPI(
    title="VisionOS AI",
    description="AI Accessibility Operating System Backend",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(
    health_router,
    prefix="/api/v1",
    tags=["Health"],
)