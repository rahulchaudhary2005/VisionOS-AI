from fastapi import Request
from fastapi.responses import JSONResponse

from app.core.exceptions import VisionOSException
from app.utils.logger import logger


async def global_exception_handler(
    request: Request,
    exc: Exception,
):
    logger.exception("Unhandled exception")

    if isinstance(exc, VisionOSException):
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "message": exc.message,
            },
        )

    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "message": "Internal Server Error",
        },
    )