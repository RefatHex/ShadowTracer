"""restrict tenant updates to name column only

Revision ID: 6cb09091c77c
Revises: 6d5b50d3e5b5
Create Date: 2026-10-03 22:32:00.535964

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = '6cb09091c77c'
down_revision: Union[str, Sequence[str], None] = '6d5b50d3e5b5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    # tenant_key (Phase 4 follow-up 1) is supposed to be permanent - the
    # application code never updates it, but until now that was only a
    # convention, not something the database enforced. The blanket
    # table-level UPDATE grant on tenants (migration 5f408777ad31) let the
    # app role update every column including tenant_key. Narrow it to a
    # column-level grant on `name` only - the one column that's actually
    # meant to be editable (display-only, per follow-up 1) - so a bug or a
    # compromised app process cannot change tenant_key no matter what the
    # Python code does, the same enforcement style as audit_log's
    # append-only grant.
    bind = op.get_bind()
    bind.execute(text(f"REVOKE UPDATE ON tenants FROM {APP_ROLE}"))
    bind.execute(text(f"GRANT UPDATE (name) ON tenants TO {APP_ROLE}"))


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(text(f"REVOKE UPDATE (name) ON tenants FROM {APP_ROLE}"))
    bind.execute(text(f"GRANT UPDATE ON tenants TO {APP_ROLE}"))
