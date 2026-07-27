from sqlalchemy import text

from app.core.system_info import SystemMonitor
from app.schemas.health import (
    AIServiceHealth,
    ApplicationHealth,
    DatabaseHealth,
    HealthResponse,
    SystemHealth,
)
from app.services.base_service import BaseService
from app.config.settings import settings


class HealthService(BaseService):

    def get_health(self) -> HealthResponse:

        database_status = "connected"

        try:
            self.db.execute(text("SELECT 1"))
        except Exception:
            database_status = "disconnected"

        return HealthResponse(
            success=True,

            application=ApplicationHealth(
                name="VisionOS AI",
                version=settings.APP_VERSION,
                uptime=SystemMonitor.uptime(),
            ),

            database=DatabaseHealth(
                status=database_status
            ),

            system=SystemHealth(
                cpu_percent=SystemMonitor.cpu_usage(),
                memory_percent=SystemMonitor.memory_usage(),
                disk_percent=SystemMonitor.disk_usage(),
                operating_system=SystemMonitor.operating_system(),
                hostname=SystemMonitor.hostname(),
                python_version=SystemMonitor.python_version(),
                boot_time=SystemMonitor.boot_time(),
            ),

            ollama=AIServiceHealth(
                status="not_configured"
            ),

            chromadb=AIServiceHealth(
                status="not_configured"
            ),

            ocr=AIServiceHealth(
                status="not_installed"
            ),
        )