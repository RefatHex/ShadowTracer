"""phase 6.5 A1: CIRCL hashlookup free layer - global known-good cache + incident known-good marker

Revision ID: c7a1e3f05b92
Revises: b2d4f6a8c0e1
Create Date: 2026-11-11

- hashlookup_verdicts: a GLOBAL cache (not per tenant - CIRCL hashlookup is public known-file data,
  CC-BY) of whether a file hash is a known-good file, with its source (NSRL etc.), ~30-day TTL.
- incidents.known_good / known_good_source: set when a FIM file in the incident is a known-good
  file. The priority generated column is lowered (capped at 2) for a known-good FIM incident that
  has no threat-intel hit, so routine OS/software files stop dominating the queue. A known-good
  file never raises priority and never suppresses a real TI match.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'c7a1e3f05b92'
down_revision: Union[str, Sequence[str], None] = 'b2d4f6a8c0e1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"
_BANDS = "GREATEST(max_level, CASE WHEN ti_confidence >= 75 THEN 12 WHEN ti_confidence >= 50 THEN 8 ELSE 0 END)"


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("""
    CREATE TABLE hashlookup_verdicts (
      sha256       varchar(64) PRIMARY KEY,
      known_good   boolean NOT NULL,
      source       text,
      filename     text,
      lookup_hash  text,
      checked_at   timestamptz NOT NULL DEFAULT now(),
      expires_at   timestamptz NOT NULL
    )"""))
    conn.execute(text("CREATE INDEX hashlookup_verdicts_expiry ON hashlookup_verdicts (expires_at)"))
    conn.execute(text("ALTER TABLE incidents ADD COLUMN known_good boolean NOT NULL DEFAULT false"))
    conn.execute(text("ALTER TABLE incidents ADD COLUMN known_good_source text"))
    # a known-good FIM file with no TI hit is capped low; otherwise the existing bands apply
    conn.execute(text("ALTER TABLE incidents DROP COLUMN priority"))
    conn.execute(text(
        f"ALTER TABLE incidents ADD COLUMN priority smallint GENERATED ALWAYS AS ("
        f"CASE WHEN known_good AND COALESCE(ti_confidence, 0) < 50 THEN LEAST(max_level, 2) ELSE {_BANDS} END) STORED"))
    # vt_requests is now the shared FIM-hash funnel queue: the free CIRCL layer records its verdict
    # here, and only non-known-good hashes with a signal are later sent to VirusTotal (Phase 6.5 C).
    conn.execute(text("ALTER TABLE vt_requests ADD COLUMN known_good boolean"))
    conn.execute(text("ALTER TABLE vt_requests ADD COLUMN hashlookup_source text"))
    conn.execute(text("ALTER TABLE vt_requests ADD COLUMN funnel_reason text"))
    # served_from gains the free-layer outcomes: a known-good hash is served by hashlookup, and a
    # non-known-good hash on a VirusTotal-off tenant is closed free-layer-only.
    conn.execute(text("ALTER TABLE vt_requests DROP CONSTRAINT vt_requests_served_from_check"))
    conn.execute(text("ALTER TABLE vt_requests ADD CONSTRAINT vt_requests_served_from_check "
                      "CHECK (served_from = ANY (ARRAY['cache', 'api', 'hashlookup', 'free_only']))"))
    conn.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON hashlookup_verdicts TO {APP_ROLE}"))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("ALTER TABLE incidents DROP COLUMN priority"))
    conn.execute(text(f"ALTER TABLE incidents ADD COLUMN priority smallint GENERATED ALWAYS AS ({_BANDS}) STORED"))
    conn.execute(text("ALTER TABLE incidents DROP COLUMN known_good, DROP COLUMN known_good_source"))
    conn.execute(text("ALTER TABLE vt_requests DROP CONSTRAINT vt_requests_served_from_check"))
    conn.execute(text("ALTER TABLE vt_requests ADD CONSTRAINT vt_requests_served_from_check "
                      "CHECK (served_from = ANY (ARRAY['cache', 'api']))"))
    conn.execute(text("ALTER TABLE vt_requests DROP COLUMN known_good, DROP COLUMN hashlookup_source, DROP COLUMN funnel_reason"))
    conn.execute(text("DROP TABLE hashlookup_verdicts"))
