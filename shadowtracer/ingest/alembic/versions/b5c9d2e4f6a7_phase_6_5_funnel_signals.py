"""phase 6.5 C: funnel prevalence skip + signal gate + priority score

Revision ID: b5c9d2e4f6a7
Revises: a4e8b1c2d3f5
Create Date: 2026-11-12

Before the VirusTotal queue, two more funnel stages run (THREAT_INTEL.md §10 C): a prevalence
skip (a hash seen on more than N hosts in the tenant recently is common -> skipped_common, the
host count cached in hash_prevalence) and a signal gate (a hash with no suspicious signal is
skipped_no_signal; one with signals gets a priority_score so a limited budget is spent on the
strongest first). vt_requests gains priority_score / prioritised / signals, and served_from allows
'skipped'.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'b5c9d2e4f6a7'
down_revision: Union[str, Sequence[str], None] = 'a4e8b1c2d3f5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("ALTER TABLE vt_requests ADD COLUMN priority_score integer"))
    conn.execute(text("ALTER TABLE vt_requests ADD COLUMN prioritised boolean NOT NULL DEFAULT false"))
    conn.execute(text("ALTER TABLE vt_requests ADD COLUMN signals text[] NOT NULL DEFAULT '{}'"))
    conn.execute(text("ALTER TABLE vt_requests DROP CONSTRAINT vt_requests_served_from_check"))
    conn.execute(text("ALTER TABLE vt_requests ADD CONSTRAINT vt_requests_served_from_check "
                      "CHECK (served_from = ANY (ARRAY['cache','api','hashlookup','free_only','malwarebazaar','skipped']))"))
    conn.execute(text("""
    CREATE TABLE hash_prevalence (
      tenant_key  varchar(64) NOT NULL REFERENCES tenants(tenant_key) ON DELETE CASCADE,
      sha256      char(64)    NOT NULL,
      host_count  integer     NOT NULL,
      computed_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (tenant_key, sha256)
    )"""))
    conn.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON hash_prevalence TO {APP_ROLE}"))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("DROP TABLE hash_prevalence"))
    conn.execute(text("ALTER TABLE vt_requests DROP CONSTRAINT vt_requests_served_from_check"))
    conn.execute(text("ALTER TABLE vt_requests ADD CONSTRAINT vt_requests_served_from_check "
                      "CHECK (served_from = ANY (ARRAY['cache','api','hashlookup','free_only','malwarebazaar']))"))
    conn.execute(text("ALTER TABLE vt_requests DROP COLUMN signals"))
    conn.execute(text("ALTER TABLE vt_requests DROP COLUMN prioritised"))
    conn.execute(text("ALTER TABLE vt_requests DROP COLUMN priority_score"))
