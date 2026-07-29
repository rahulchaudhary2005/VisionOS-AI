from app.models.user import User
from app.repositories.base_repository import BaseRepository
from sqlalchemy import select, func


class UserRepository(BaseRepository):
    """Repository for user persistence operations."""

    def get_by_email(self, email: str) -> User | None:
        statement = select(User).where(User.email == email.lower().strip())
        return self.db.scalar(statement)

    def get_by_id(self, user_id: str) -> User | None:
        return self.db.get(User, user_id)

    def create(self, user: User) -> User:
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def save(self, user: User) -> User:
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def exists_by_email(self, email: str) -> bool:
        return self.get_by_email(email) is not None

    def list_all(self) -> list[User]:
      """
      Return all users ordered by email.
      """

      statement = (
        select(User)
        .order_by(User.email.asc())
      )

      return list(
        self.db.scalars(statement).all()
     )

    def search(
        self,
        keyword: str,
    ) -> list[User]:
        """
        Search for users by email or full name.
        """
        keyword = keyword.strip()

        statement = (
            select(User)
            .where(
                (User.email.ilike(f"%{keyword}%"))
                | (User.full_name.ilike(f"%{keyword}%"))
            )
            .order_by(User.email.asc())
        )

        return list(self.db.scalars(statement).all())

    def count(self) -> int:
        """
        Count the total number of users.
        """
        statement = select(func.count(User.id))
        return self.db.scalar(statement) or 0

    def delete(self, user: User) -> None:
        """
        Permanently delete a user from the database.
        """
        self.db.delete(user)
        self.db.commit()
