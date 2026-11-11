"""phase 6.5 C: generic paid-source verdict cache + call accounting

Revision ID: a4e8b1c2d3f5
Revises: f3a7c9e1d2b4
Create Date: 2026-11-12

source_verdicts caches one verdict per (tenant, source, indicator) with a per-source TTL, so a
hash or IP already looked up is not paid for again inside the window - serves the MalwareBazaar
funnel stage and the on-demand AbuseIPDB/GreyNoise IP lookups. source_calls records every outbound
call (one row), so the per-tenant daily_budget and the 429 cooldown can be computed per (tenant,
source). vt_requests.funnel_reason already carries the per-hash reason code; a new mbz_checked
column marks that the MalwareBazaar stage has run so the VirusTotal stage does not re-ask it.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'a4e8b1c2d3f5'
down_revision: Union[str, Sequence[str], None] = 'f3a7c9e1d2b4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"
SOURCES = "'virustotal','malwarebazaar','abuseipdb','greynoise'"


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text(f"""
    CREATE TABLE source_verdicts (
      tenant_key     varchar(64) NOT NULL REFERENCES tenants(tenant_key) ON DELETE CASCADE,
      source         text        NOT NULL CHECK (source IN ({SOURCES})),
      indicator      text        NOT NULL,                      -- sha256 (hash sources) or IP (ip sources)
      indicator_type text        NOT NULL CHECK (indicator_type IN ('sha256','ipv4','ipv6')),
      status         text        NOT NULL,                      -- malicious | clean | unknown | suspicious
      data           jsonb       NOT NULL DEFAULT '{{}}'::jsonb, -- signature/tags/first_seen/score/...
      fetched_at     timestamptz NOT NULL DEFAULT now(),
      expires_at     timestamptz NOT NULL,
      PRIMARY KEY (tenant_key, source, indicator)
    )"""))
    conn.execute(text("CREATE INDEX source_verdicts_live ON source_verdicts (tenant_key, source, expires_at)"))
    conn.execute(text(f"""
    CREATE TABLE source_calls (
      id          bigserial PRIMARY KEY,
      tenant_key  varchar(64) NOT NULL,
      source      text        NOT NULL CHECK (source IN ({SOURCES})),
      indicator   text        NOT NULL,
      called_at   timestamptz NOT NULL DEFAULT now(),
      http_status integer,
      outcome     text
    )"""))
    conn.execute(text("CREATE INDEX source_calls_budget ON source_calls (tenant_key, source, called_at)"))
    # mark that the MalwareBazaar stage has already run for a pending request
    conn.execute(text("ALTER TABLE vt_requests ADD COLUMN mbz_checked boolean NOT NULL DEFAULT false"))
    # a MalwareBazaar hit resolves a request without a VirusTotal call, and annotates the incident
    conn.execute(text("ALTER TABLE vt_requests DROP CONSTRAINT vt_requests_served_from_check"))
    conn.execute(text("ALTER TABLE vt_requests ADD CONSTRAINT vt_requests_served_from_check "
                      "CHECK (served_from = ANY (ARRAY['cache','api','hashlookup','free_only','malwarebazaar']))"))
    conn.execute(text("ALTER TABLE incident_ti DROP CONSTRAINT incident_ti_origin_check"))
    conn.execute(text("ALTER TABLE incident_ti ADD CONSTRAINT incident_ti_origin_check "
                      "CHECK (origin = ANY (ARRAY['matcher','virustotal','retro','malwarebazaar']))"))
    conn.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON source_verdicts TO {APP_ROLE}"))
    conn.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON source_calls TO {APP_ROLE}"))
    conn.execute(text(f"GRANT USAGE, SELECT ON SEQUENCE source_calls_id_seq TO {APP_ROLE}"))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("ALTER TABLE incident_ti DROP CONSTRAINT incident_ti_origin_check"))
    conn.execute(text("ALTER TABLE incident_ti ADD CONSTRAINT incident_ti_origin_check "
                      "CHECK (origin = ANY (ARRAY['matcher','virustotal','retro']))"))
    conn.execute(text("ALTER TABLE vt_requests DROP CONSTRAINT vt_requests_served_from_check"))
    conn.execute(text("ALTER TABLE vt_requests ADD CONSTRAINT vt_requests_served_from_check "
                      "CHECK (served_from = ANY (ARRAY['cache','api','hashlookup','free_only']))"))
    conn.execute(text("ALTER TABLE vt_requests DROP COLUMN mbz_checked"))
    conn.execute(text("DROP TABLE source_calls"))
    conn.execute(text("DROP TABLE source_verdicts"))
