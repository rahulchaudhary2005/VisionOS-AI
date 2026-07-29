from app.config.settings import settings
from app.utils.logger import logger


def validate_startup() -> None:
    logger.info("Validating application configuration...")

    required = {
        "SECRET_KEY": settings.SECRET_KEY,
        "JWT_SECRET": settings.JWT_SECRET,
        "DATABASE_URL": settings.DATABASE_URL,
        "OLLAMA_URL": settings.OLLAMA_URL,
    }

    missing = [key for key, value in required.items() if not value]

    if missing:
        raise RuntimeError(
            f"Missing required environment variables: {', '.join(missing)}"
        )

    logger.info("Startup validation completed successfully.")
