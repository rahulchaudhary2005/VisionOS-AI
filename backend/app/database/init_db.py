from app.database.base import Base
from app.database.database import engine


def create_database():
    Base.metadata.create_all(bind=engine)
