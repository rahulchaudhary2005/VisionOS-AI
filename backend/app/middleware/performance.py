import time

from app.config.settings import settings
from app.core.metrics import metrics
from app.utils.logger import logger
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class PerformanceMiddleware(BaseHTTPMiddleware):
    """
    Tracks request duration and API metrics.
    """

    async def dispatch(self, request: Request, call_next):
        metrics.request_started()

        start = time.perf_counter()

        response = await call_next(request)

        elapsed_ms = (time.perf_counter() - start) * 1000

        metrics.request_finished(
            duration_ms=elapsed_ms,
            status_code=response.status_code,
        )

        response.headers["X-Process-Time"] = f"{elapsed_ms:.2f} ms"
        response.headers["X-API-Version"] = settings.APP_VERSION

        logger.info(
            "%s %s | %s | %.2f ms",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
        )

        if elapsed_ms >= 500:
            logger.warning(
                "Slow request detected: %s %.2f ms",
                request.url.path,
                elapsed_ms,
            )

        return response
