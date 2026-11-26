"""phase 9 Part B: grant DELETE on soar_allowlist (admins remove allowlist CIDRs via the console)"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'a7c9e1f3b5d8'
down_revision: Union[str, Sequence[str], None] = 'f3b5d7a9c1e4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    op.get_bind().execute(text(f"GRANT DELETE ON soar_allowlist TO {APP_ROLE}"))


def downgrade() -> None:
    op.get_bind().execute(text(f"REVOKE DELETE ON soar_allowlist FROM {APP_ROLE}"))
