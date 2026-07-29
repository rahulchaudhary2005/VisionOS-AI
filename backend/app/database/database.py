from app.config.settings import settings
from sqlalchemy import create_engine

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False,
)
