"""create users and token_blacklist tables

Revision ID: 0001_create_users_and_token_blacklist
Revises: None
Create Date: 2026-07-27 00:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0001_create_users_and_token_blacklist"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False, unique=True),
        sa.Column("full_name", sa.String(length=255), nullable=True),
        sa.Column("hashed_password", sa.Text(), nullable=False),
        sa.Column(
            "role",
            sa.Enum(
                "admin", "moderator", "user", "ai_engine", "service", name="user_role"
            ),
            nullable=False,
            server_default=sa.text("'user'"),
        ),
        sa.Column(
            "status",
            sa.Enum(
                "active",
                "inactive",
                "pending",
                "suspended",
                "locked",
                "deleted",
                name="user_status",
            ),
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column(
            "is_superuser",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("FALSE"),
        ),
        sa.Column(
            "is_verified", sa.Boolean(), nullable=False, server_default=sa.text("FALSE")
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )

    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "token_blacklist",
        sa.Column(
            "id", sa.Integer(), primary_key=True, autoincrement=True, nullable=False
        ),
        sa.Column("jti", sa.String(length=64), nullable=False, unique=True),
        sa.Column("token_type", sa.String(length=20), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column(
            "revoked_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
    )

    op.create_index("ix_token_blacklist_jti", "token_blacklist", ["jti"], unique=True)
    op.create_index("ix_token_blacklist_user_id", "token_blacklist", ["user_id"])


def downgrade() -> None:
    op.drop_table("token_blacklist")
    op.drop_table("users")
