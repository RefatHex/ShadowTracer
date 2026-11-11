"""phase 6.5 A4: Tor exit node context feed - a low-severity tag, never an alert

Revision ID: e2c5a7d9b0f3
Revises: d1b4c6e8f2a0
Create Date: 2026-11-12

tor_exit_nodes: the current Tor exit list (CC0, check.torproject.org/torbulkexitlist), refreshed by
ti-sync. incidents.tor_exit_ips: the subset of an incident's source IPs that are Tor exit nodes,
set by a ti-sync tagging pass. It is context only - shown to analysts, never an alert on its own,
and it does not change priority.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'e2c5a7d9b0f3'
down_revision: Union[str, Sequence[str], None] = 'd1b4c6e8f2a0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("""
    CREATE TABLE tor_exit_nodes (
      ip         text PRIMARY KEY,
      first_seen timestamptz NOT NULL DEFAULT now(),
      last_seen  timestamptz NOT NULL DEFAULT now()
    )"""))
    conn.execute(text("ALTER TABLE incidents ADD COLUMN tor_exit_ips varchar[] NOT NULL DEFAULT '{}'"))
    conn.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON tor_exit_nodes TO {APP_ROLE}"))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("ALTER TABLE incidents DROP COLUMN tor_exit_ips"))
    conn.execute(text("DROP TABLE tor_exit_nodes"))
