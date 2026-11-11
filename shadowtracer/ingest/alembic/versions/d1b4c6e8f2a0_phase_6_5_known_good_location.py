"""phase 6.5 A1 fix: known-good priority depends on the file's location, not just the verdict

Revision ID: d1b4c6e8f2a0
Revises: c7a1e3f05b92
Create Date: 2026-11-12

A CIRCL known-good verdict no longer lowers priority on its own. known_good stays as the context
flag ("a known file is present"); a new known_good_safe flag - set only for an expected install
location with a non-dual-use name - is what the priority column lowers on. A known-good file in a
high-risk path (temp, web roots, cron/systemd/startup, home downloads) or a dual-use tool
(nc/nmap/socat/…) keeps its priority, and known_good_note carries the label shown to analysts.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'd1b4c6e8f2a0'
down_revision: Union[str, Sequence[str], None] = 'c7a1e3f05b92'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_BANDS = "GREATEST(max_level, CASE WHEN ti_confidence >= 75 THEN 12 WHEN ti_confidence >= 50 THEN 8 ELSE 0 END)"
_OLD = (f"CASE WHEN known_good AND COALESCE(ti_confidence, 0) < 50 THEN LEAST(max_level, 2) ELSE {_BANDS} END")
_NEW = (f"CASE WHEN known_good_safe AND COALESCE(ti_confidence, 0) < 50 THEN LEAST(max_level, 2) ELSE {_BANDS} END")


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("ALTER TABLE incidents ADD COLUMN known_good_safe boolean NOT NULL DEFAULT false"))
    conn.execute(text("ALTER TABLE incidents ADD COLUMN known_good_note text"))
    # existing known-good incidents were down-ranked under the old rule; keep that (lab only)
    conn.execute(text("UPDATE incidents SET known_good_safe = true, known_good_note = 'known file' WHERE known_good"))
    conn.execute(text("ALTER TABLE incidents DROP COLUMN priority"))
    conn.execute(text(f"ALTER TABLE incidents ADD COLUMN priority smallint GENERATED ALWAYS AS ({_NEW}) STORED"))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("ALTER TABLE incidents DROP COLUMN priority"))
    conn.execute(text(f"ALTER TABLE incidents ADD COLUMN priority smallint GENERATED ALWAYS AS ({_OLD}) STORED"))
    conn.execute(text("ALTER TABLE incidents DROP COLUMN known_good_safe, DROP COLUMN known_good_note"))
