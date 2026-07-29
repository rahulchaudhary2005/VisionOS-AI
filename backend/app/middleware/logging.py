"""
Enterprise HTTP Logging Middleware for VisionOS AI.

This middleware provides structured request/response logging and integrates
with the RequestIDMiddleware by automatically attaching the request ID to
every log entry.

Responsibilities
----------------
- Logs incoming requests
- Logs completed responses
- Logs unhandled exceptions
- Measures request latency
- Correlates logs using X-Request-ID
- Never modifies business logic
- Production-safe (no request body logging)
"""

from __future__ import annotations

import time
from typing import Any

from app.utils.logger import logger
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Enterprise HTTP logging middleware.

    This middleware is intentionally lightweight and should only be responsible
    for structured request lifecycle logging.

    Authentication, authorization, validation and business logic belong
    elsewhere.
    """

    async def dispatch(
        self,
        request: Request,
        call_next,
    ) -> Response:
        """
        Process an incoming request while logging request/response details.
        """

        start = time.perf_counter()

        request_id = getattr(request.state, "request_id", "-")

        client_ip = (
            request.headers.get("X-Forwarded-For")
            or (request.client.host if request.client else "unknown")
        )

        user_agent = request.headers.get("User-Agent", "unknown")

        logger.info(
            (
                "HTTP Request Started | "
                "request_id=%s "
                "method=%s "
                "path=%s "
                "client_ip=%s "
                "user_agent=%s"
            ),
            request_id,
            request.method,
            request.url.path,
            client_ip,
            user_agent,
        )

        try:
            response = await call_next(request)

        except Exception:
            elapsed_ms = (time.perf_counter() - start) * 1000

            logger.exception(
                (
                    "HTTP Request Failed | "
                    "request_id=%s "
                    "method=%s "
                    "path=%s "
                    "duration_ms=%.2f"
                ),
                request_id,
                request.method,
                request.url.path,
                elapsed_ms,
            )
            raise

        elapsed_ms = (time.perf_counter() - start) * 1000

        user_id = self._extract_user(request)

        logger.info(
            (
                "HTTP Request Completed | "
                "request_id=%s "
                "user=%s "
                "method=%s "
                "path=%s "
                "status=%s "
                "duration_ms=%.2f"
            ),
            request_id,
            user_id,
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
        )

        return response

    @staticmethod
    def _extract_user(request: Request) -> str:
        """
        Extract authenticated user information if available.

        Authentication middleware may optionally attach the authenticated
        user object to request.state.user.

        This middleware does not depend on authentication and therefore
        gracefully handles anonymous requests.
        """

        user: Any | None = getattr(request.state, "user", None)

        if user is None:
            return "anonymous"

        return (
            getattr(user, "email", None)
            or getattr(user, "id", None)
            or "authenticated"
        )
