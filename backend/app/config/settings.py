from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "VisionOS AI"

    APP_VERSION: str = "1.0.0"

    APP_ENV: str = "development"

    BACKEND_PORT: int = 8000

    FRONTEND_PORT: int = 5173

    SECRET_KEY: str

    JWT_SECRET: str

    DATABASE_URL: str

    OLLAMA_URL: str

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
