"""phase 4 audit log and restricted app role

Revision ID: 5f408777ad31
Revises: 8134f2ed1958
Create Date: 2026-10-03 05:50:00.000000

"""
import os
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = '5f408777ad31'
down_revision: Union[str, Sequence[str], None] = '8134f2ed1958'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("tenant_id", sa.Integer, nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("target", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("outcome", sa.String(20), nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("row_hash", sa.String(64), nullable=False),
    )

    bind = op.get_bind()

    # The console backend connects as this role, not the table owner -
    # see app/config.py. APP_DB_PASSWORD must be set (same *_FILE
    # convention as every other secret in this project); refuse to
    # silently create a passwordless/role-less setup.
    app_db_password = os.environ.get("APP_DB_PASSWORD") or _read_file_secret("APP_DB_PASSWORD_FILE")
    if not app_db_password:
        raise RuntimeError(
            "APP_DB_PASSWORD (or APP_DB_PASSWORD_FILE) must be set in the environment "
            "running this migration - see deploy/lab/.env.example"
        )

    role_exists = bind.execute(
        text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": APP_ROLE}
    ).first()
    if role_exists:
        bind.execute(text(f"ALTER ROLE {APP_ROLE} WITH PASSWORD :password"), {"password": app_db_password})
    else:
        # Role name is a fixed, trusted constant (not user input), so
        # interpolating it directly is fine; the password is still bound
        # as a parameter.
        bind.execute(text(f"CREATE ROLE {APP_ROLE} LOGIN PASSWORD :password"), {"password": app_db_password})

    # Ordinary CRUD tables: the app role needs the usual four.
    for table in ("tenants", "users", "refresh_tokens", "login_attempts"):
        bind.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {APP_ROLE}"))
        bind.execute(text(f"GRANT USAGE, SELECT ON {table}_id_seq TO {APP_ROLE}"))

    # audit_log: append-only, enforced here, not just in application code.
    # No UPDATE/DELETE grant at all (not even revoked-after-granting - it
    # is simply never granted), so a compromised or buggy app process
    # cannot alter or remove a row no matter what the Python code does.
    bind.execute(text(f"GRANT SELECT, INSERT ON audit_log TO {APP_ROLE}"))
    bind.execute(text(f"GRANT USAGE, SELECT ON audit_log_id_seq TO {APP_ROLE}"))
    # Explicit REVOKE too, not just an absent GRANT - makes the
    # restriction self-documenting and robust against someone later
    # adding a blanket "GRANT ALL ON ALL TABLES".
    bind.execute(text(f"REVOKE UPDATE, DELETE ON audit_log FROM {APP_ROLE}"))


def _read_file_secret(env_name: str) -> str | None:
    path = os.environ.get(env_name)
    if not path:
        return None
    with open(path) as f:
        return f.read().strip()


def downgrade() -> None:
    bind = op.get_bind()
    for table in ("tenants", "users", "refresh_tokens", "login_attempts", "audit_log"):
        bind.execute(text(f"REVOKE ALL ON {table} FROM {APP_ROLE}"))
    op.drop_table("audit_log")
