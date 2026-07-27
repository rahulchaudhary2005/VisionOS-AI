from app.schemas.base import BaseSchema


class ApplicationHealth(BaseSchema):
    name: str
    version: str
    uptime: str


class DatabaseHealth(BaseSchema):
    status: str


class SystemHealth(BaseSchema):
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    operating_system: str
    hostname: str
    python_version: str
    boot_time: str


class AIServiceHealth(BaseSchema):
    status: str


class HealthResponse(BaseSchema):
    success: bool

    application: ApplicationHealth

    database: DatabaseHealth

    system: SystemHealth

    ollama: AIServiceHealth

    chromadb: AIServiceHealth

    ocr: AIServiceHealth