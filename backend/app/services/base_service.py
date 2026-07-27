from sqlalchemy.orm import Session


class BaseService:
    """
    Base class for all application services.

    Stores the database session and provides
    common functionality for child services.
    """

    def __init__(self, db: Session):
        self.db = db
        