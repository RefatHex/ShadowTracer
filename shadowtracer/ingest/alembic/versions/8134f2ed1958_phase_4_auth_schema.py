"""phase 4 auth schema

Revision ID: 8134f2ed1958
Revises: 28c160a86fbb
Create Date: 2026-10-03 05:22:16.163025

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8134f2ed1958'
down_revision: Union[str, Sequence[str], None] = '28c160a86fbb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer, sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("role IN ('admin', 'analyst', 'viewer')", name="users_role_check"),
        sa.UniqueConstraint("tenant_id", "email", name="users_tenant_email_unique"),
    )

    # One row per currently/previously-issued refresh token. Rotation:
    # redeeming a token marks it used_at and inserts the next token in the
    # same family_id. Replaying an already-used token (used_at not null)
    # means the token was stolen after rotation - the whole family is
    # revoked on sight (see app/auth.py's refresh logic, Phase 4 Step 2).
    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("family_id", sa.String(36), nullable=False),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("family_revoked", sa.Boolean, nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_refresh_tokens_family_id", "refresh_tokens", ["family_id"])

    # Lockout source of truth: both per-IP and per-account lockout are
    # computed by counting recent rows here, not a separate counter table -
    # one source of truth, no risk of a counter drifting from reality.
    op.create_table(
        "login_attempts",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("email", sa.String(255), nullable=True),
        sa.Column("success", sa.Boolean, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_login_attempts_ip_created_at", "login_attempts", ["ip", "created_at"])
    op.create_index("ix_login_attempts_email_created_at", "login_attempts", ["email", "created_at"])


def downgrade() -> None:
    op.drop_table("login_attempts")
    op.drop_table("refresh_tokens")
    op.drop_table("users")
    op.drop_table("tenants")
