from typing import Generator

from app.database.database import engine
from sqlalchemy.orm import sessionmaker

SessionLocal = sessionmaker(
    autoflush=False,
    autocommit=False,
    bind=engine,
)


def get_db() -> Generator:

    db = SessionLocal()

    try:

        yield db

    finally:

        db.close()
