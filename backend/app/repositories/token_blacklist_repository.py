from datetime import datetime

from app.models.token_blacklist import TokenBlacklist
from app.repositories.base_repository import BaseRepository
from sqlalchemy import exists, select


class TokenBlacklistRepository(BaseRepository):
    """Repository for managing revoked JWT identifiers."""

    def add(
        self,
        jti: str,
        token_type: str,
        user_id: str,
        expires_at: datetime,
        reason: str | None = None,
    ) -> TokenBlacklist:
        blacklist_entry = TokenBlacklist(
            jti=jti,
            token_type=token_type,
            user_id=user_id,
            expires_at=expires_at,
            reason=reason,
        )
        self.db.add(blacklist_entry)
        self.db.commit()
        self.db.refresh(blacklist_entry)
        return blacklist_entry

    def is_blacklisted(self, jti: str) -> bool:
        statement = select(exists().where(TokenBlacklist.jti == jti))
        return bool(self.db.scalar(statement))

    def purge_expired(self) -> int:
        expired_entries = self.db.query(TokenBlacklist).filter(
            TokenBlacklist.expires_at <= datetime.utcnow()
        )
        count = expired_entries.count()
        if count:
            expired_entries.delete(synchronize_session=False)
            self.db.commit()
        return count
