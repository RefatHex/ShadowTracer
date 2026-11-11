"""phase 6.5 A3: CISA KEV + FIRST EPSS enrichment of CVE ids seen in alerts

Revision ID: c6f1a3b5d7e9
Revises: b5c9d2e4f6a7
Create Date: 2026-11-12

In 4.14.8 the vulnerability-detection module writes to the Wazuh indexer, which ShadowTracer does
not run, so CVE findings never reach alerts.json / the ClickHouse events map (verified: 0 events
with a vulnerability rule group, while 6,895 events carry a CVE id inside a rule description). So
A3 does NOT ingest vulnerability-detector findings; it enriches any CVE id that appears in an
alert. kev_vulnerabilities is CISA's Known Exploited Vulnerabilities catalog (CC0); epss_scores is
FIRST EPSS (exploit-probability) for the CVEs we actually see. Incidents whose alerts mention a CVE
are tagged with the CVE ids, which are in KEV, and the max EPSS - KEV (actively exploited) raises
priority. Package-level KEV watchlisting and full vuln management are backlog (syscollector package
inventory is not in the ClickHouse pipeline).
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'c6f1a3b5d7e9'
down_revision: Union[str, Sequence[str], None] = 'b5c9d2e4f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"

# A1 priority expression wrapped in a KEV floor (13) - an actively-exploited CVE raises priority.
_PRIORITY_KEV = (
    "GREATEST("
    "CASE WHEN known_good_safe AND COALESCE(ti_confidence, 0) < 50 THEN LEAST(max_level, 2) "
    "ELSE GREATEST(max_level, CASE WHEN ti_confidence >= 75 THEN 12 WHEN ti_confidence >= 50 THEN 8 ELSE 0 END) END, "
    "CASE WHEN cardinality(kev_cve_ids) > 0 THEN 13 ELSE 0 END)")
_PRIORITY_A1 = (
    "CASE WHEN known_good_safe AND COALESCE(ti_confidence, 0) < 50 THEN LEAST(max_level, 2) "
    "ELSE GREATEST(max_level, CASE WHEN ti_confidence >= 75 THEN 12 WHEN ti_confidence >= 50 THEN 8 ELSE 0 END) END")


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("""
    CREATE TABLE kev_vulnerabilities (
      cve_id              text PRIMARY KEY,
      vendor_project      text,
      product             text,
      vulnerability_name  text,
      date_added          date,
      due_date            date,
      known_ransomware    boolean NOT NULL DEFAULT false,
      refreshed_at        timestamptz NOT NULL DEFAULT now()
    )"""))
    conn.execute(text("""
    CREATE TABLE epss_scores (
      cve_id      text PRIMARY KEY,
      epss        double precision NOT NULL,
      percentile  double precision,
      scored_date date,
      refreshed_at timestamptz NOT NULL DEFAULT now()
    )"""))
    conn.execute(text("ALTER TABLE incidents ADD COLUMN cve_ids text[] NOT NULL DEFAULT '{}'"))
    conn.execute(text("ALTER TABLE incidents ADD COLUMN kev_cve_ids text[] NOT NULL DEFAULT '{}'"))
    conn.execute(text("ALTER TABLE incidents ADD COLUMN max_epss double precision"))
    conn.execute(text("ALTER TABLE incidents ADD COLUMN cve_enriched_at timestamptz"))
    # an incident with a KEV (actively-exploited) CVE is floored to priority 13. priority is a
    # generated column, so redefine it (drop + re-add) to include the KEV floor.
    conn.execute(text("ALTER TABLE incidents DROP COLUMN priority"))
    conn.execute(text(f"ALTER TABLE incidents ADD COLUMN priority smallint GENERATED ALWAYS AS ({_PRIORITY_KEV}) STORED"))
    for tbl in ("kev_vulnerabilities", "epss_scores"):
        conn.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {tbl} TO {APP_ROLE}"))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("ALTER TABLE incidents DROP COLUMN priority"))
    for col in ("cve_enriched_at", "max_epss", "kev_cve_ids", "cve_ids"):
        conn.execute(text(f"ALTER TABLE incidents DROP COLUMN {col}"))
    conn.execute(text(f"ALTER TABLE incidents ADD COLUMN priority smallint GENERATED ALWAYS AS ({_PRIORITY_A1}) STORED"))
    conn.execute(text("DROP TABLE epss_scores"))
    conn.execute(text("DROP TABLE kev_vulnerabilities"))
