from contextlib import asynccontextmanager

from app.api.routes.auth import router as auth_router
from app.api.routes.health import router as health_router
from app.api.routes.register import router as register_router
from app.core.exceptions import VisionOSException
from app.core.startup import validate_startup
from app.database.init_db import create_database
from app.middleware.error_handler import global_exception_handler
from app.middleware.performance import PerformanceMiddleware
from app.middleware.request_id import RequestIDMiddleware
from app.utils.logger import logger
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.middleware.logging import LoggingMiddleware

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting VisionOS AI Backend...")

    validate_startup()

    create_database()

    logger.info("âœ… Database initialized successfully.")

    yield

    logger.info("ðŸ›‘ Shutting down VisionOS AI Backend...")


app = FastAPI(
    title="VisionOS AI",
    description="AI Accessibility Operating System Backend",
    version="1.0.0",
    lifespan=lifespan,
)

# -----------------------------
# Exception Handlers
# -----------------------------
app.add_exception_handler(
    VisionOSException,
    global_exception_handler,
)

# -----------------------------
# Middleware
# -----------------------------
app.add_middleware(RequestIDMiddleware)
app.add_middleware(LoggingMiddleware)
app.add_middleware(PerformanceMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Routes
# -----------------------------
app.include_router(
    health_router,
    prefix="/api/v1",
    tags=["Health"],
)

app.include_router(
    auth_router,
    prefix="/api/v1",
    tags=["Authentication"],
)

app.include_router(
    register_router,
    prefix="/api/v1",
    tags=["Authentication"],
)
