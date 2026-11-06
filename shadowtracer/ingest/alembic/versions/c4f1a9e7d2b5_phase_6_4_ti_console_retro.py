"""phase 6.4: TI in the console, false-positive feedback, per-tenant feed choice, retro-hunt

Revision ID: c4f1a9e7d2b5
Revises: b7e2c4d91f03
Create Date: 2026-11-06

- incident_ti.origin: matcher | virustotal | retro.
- ti_feedback: analyst labels on TI hits (false_positive) for the ML phase; the observable
  also goes to the tenant's allowlist (kind fp_marking), which stops future matches for
  that tenant only.
- ti_tenant_settings.disabled_sources: global feeds a tenant does not want matched.
- ti_key_status: whether a key is configured per source and tenant (written by ti-sync,
  which holds the keys) - yes/no only, never the value.
- ti_retro_state: per-tenant retro-hunt cursor (IOCs created after it are hunted).
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'c4f1a9e7d2b5'
down_revision: Union[str, Sequence[str], None] = 'b7e2c4d91f03'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("""
    ALTER TABLE incident_ti ADD COLUMN origin text NOT NULL DEFAULT 'matcher'
        CHECK (origin IN ('matcher', 'virustotal', 'retro'));
    UPDATE incident_ti SET origin = 'virustotal' WHERE 'virustotal' = ANY(sources);
    CREATE TABLE ti_feedback (
      id              bigserial PRIMARY KEY,
      tenant_key      varchar(64) NOT NULL REFERENCES tenants(tenant_key),
      incident_ti_id  bigint REFERENCES incident_ti(id),
      ioc_id          bigint REFERENCES iocs(id),
      observable_type text NOT NULL,
      observable      text NOT NULL,
      sources         text[] NOT NULL DEFAULT '{}',
      label           text NOT NULL CHECK (label IN ('false_positive')),
      reason          text NOT NULL,
      created_by      text NOT NULL,
      created_at      timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX ti_feedback_tenant ON ti_feedback (tenant_key, created_at);
    ALTER TABLE ti_tenant_settings ADD COLUMN disabled_sources text[] NOT NULL DEFAULT '{}';
    CREATE TABLE ti_key_status (
      name        text NOT NULL,
      tenant_key  text NULL,
      configured  boolean NOT NULL,
      updated_at  timestamptz NOT NULL DEFAULT now(),
      UNIQUE NULLS NOT DISTINCT (name, tenant_key)
    );
    CREATE TABLE ti_retro_state (
      tenant_key  varchar(64) PRIMARY KEY REFERENCES tenants(tenant_key),
      cursor      timestamptz NOT NULL,
      last_run_at timestamptz,
      last_counts jsonb NOT NULL DEFAULT '{}'
    );
    """))
    for t in ("ti_feedback", "ti_key_status", "ti_retro_state"):
        conn.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {t} TO {APP_ROLE}"))
    conn.execute(text(f"GRANT USAGE, SELECT ON SEQUENCE ti_feedback_id_seq TO {APP_ROLE}"))


def downgrade() -> None:
    op.get_bind().execute(text(
        "DROP TABLE ti_retro_state, ti_key_status, ti_feedback; "
        "ALTER TABLE ti_tenant_settings DROP COLUMN disabled_sources; ALTER TABLE incident_ti DROP COLUMN origin"))
