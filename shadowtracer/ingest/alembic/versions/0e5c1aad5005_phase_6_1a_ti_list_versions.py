"""phase 6.1a: TI list version per manager node, for /health/detail

Revision ID: 0e5c1aad5005
Revises: 9db37e0dcbaa
Create Date: 2026-11-05

THREAT_INTEL.md §4.16 and 6.1a item 3: the safe reload wrapper
(shadowtracer/intel/shadowtracer_intel/safe_reload.py) records, for every
tenant manager node, the checksum of every ShadowTracer TI file it holds
(lists, their compiled .cdb, the TI rule file) and the result of the last
distribution/reload (ok, unchanged, warnings, errors, sync_timeout,
rolled_back, rejected). console-backend's /health/detail shows it and flags a
node whose files differ from its master's or whose last result was not ok.
One row per (tenant, node, file); path '*' carries a result that has no file
(a rejected bundle is never written anywhere).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text

revision: str = '0e5c1aad5005'
down_revision: Union[str, Sequence[str], None] = '9db37e0dcbaa'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    op.create_table(
        "ti_list_versions",
        sa.Column("tenant_key", sa.Text, nullable=False),
        sa.Column("node", sa.Text, nullable=False),
        sa.Column("path", sa.Text, nullable=False),
        sa.Column("role", sa.Text, nullable=False),
        sa.Column("sha256", sa.Text, nullable=True),
        sa.Column("entries", sa.Integer, nullable=True),
        sa.Column("result", sa.Text, nullable=False),
        sa.Column("detail", sa.Text, nullable=False, server_default=""),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("tenant_key", "node", "path"),
    )
    # console-backend reads it as the app role; ti-sync (6.1b) writes it as the app role.
    op.get_bind().execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ti_list_versions TO {APP_ROLE}"))


def downgrade() -> None:
    op.drop_table("ti_list_versions")
