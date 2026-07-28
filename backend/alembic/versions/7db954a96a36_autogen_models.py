"""autogen models

Revision ID: 7db954a96a36
Revises: 0001_create_users_and_token_blacklist
Create Date: 2026-07-28 09:41:28.958869

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "7db954a96a36"
down_revision: Union[str, Sequence[str], None] = "0001_create_users_and_token_blacklist"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# NOTE: Alembic autogenerate emitted table/enum creation. We harden the
# migration to explicitly create/destroy ENUM types when running against
# PostgreSQL, while leaving SQLite/others unaffected. This makes the
# revision safe for CI and production.


def upgrade() -> None:
    """Upgrade schema: create enums (Postgres) then tables/indexes."""
    bind = op.get_bind()
    dialect_name = bind.dialect.name

    # Define enum objects so they can be created/dropped explicitly
    user_role = sa.Enum(
        "ADMIN",
        "MODERATOR",
        "USER",
        "AI_ENGINE",
        "SERVICE",
        name="user_role",
    )
    user_status = sa.Enum(
        "ACTIVE",
        "INACTIVE",
        "PENDING",
        "SUSPENDED",
        "LOCKED",
        "DELETED",
        name="user_status",
    )

    # Create enums explicitly for Postgres to avoid 'type already exists' errors
    if dialect_name == "postgresql":
        user_role.create(bind, checkfirst=True)
        user_status.create(bind, checkfirst=True)

    # Create tables and indexes
    op.create_table(
        "token_blacklist",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("jti", sa.String(length=64), nullable=False),
        sa.Column("token_type", sa.String(length=20), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_token_blacklist_jti"), "token_blacklist", ["jti"], unique=True
    )
    op.create_index(
        op.f("ix_token_blacklist_user_id"), "token_blacklist", ["user_id"], unique=False
    )

    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=True),
        sa.Column("hashed_password", sa.Text(), nullable=False),
        sa.Column("role", user_role, nullable=False),
        sa.Column("status", user_status, nullable=False),
        sa.Column("is_superuser", sa.Boolean(), nullable=False),
        sa.Column("is_verified", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id"),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)


def downgrade() -> None:
    """Downgrade schema: drop tables then enums (Postgres)."""
    bind = op.get_bind()
    dialect_name = bind.dialect.name

    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.drop_table("users")
    op.drop_index(op.f("ix_token_blacklist_user_id"), table_name="token_blacklist")
    op.drop_index(op.f("ix_token_blacklist_jti"), table_name="token_blacklist")
    op.drop_table("token_blacklist")

    # Drop enum types explicitly on Postgres
    if dialect_name == "postgresql":
        user_role = sa.Enum(
            "ADMIN",
            "MODERATOR",
            "USER",
            "AI_ENGINE",
            "SERVICE",
            name="user_role",
        )
        user_status = sa.Enum(
            "ACTIVE",
            "INACTIVE",
            "PENDING",
            "SUSPENDED",
            "LOCKED",
            "DELETED",
            name="user_status",
        )

        user_role.drop(bind, checkfirst=True)
        user_status.drop(bind, checkfirst=True)
