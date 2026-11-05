"""phase 6.1c: ti-matcher - incident_ti, incident priority, IOC store version

Revision ID: 7c1e9b2f4a60
Revises: 14998d8588fb
Create Date: 2026-11-06

shadowtracer/docs/design/THREAT_INTEL.md §3.1. ti-matcher annotates alerts a native
rule already produced; it never changes the alert.

- incident_ti: one row per (alert, IOC). incident_id is filled in once the correlator
  has put the alert in an incident (the matcher may see the alert first).
- incidents.ti_confidence: highest confidence of the incident's TI matches, written
  only by ti-matcher. incidents.priority is generated from it, so the correlator never
  writes or races it: GREATEST(max_level, 12 if C >= 75, 8 if C >= 50) - the same bands
  as the CDB TI rules (§4.10).
- ti_store_version: one counter bumped by a statement trigger on every IOC store change
  that can change what matches (not the confidence write-back of list generation).
  ti-matcher polls it and reloads its sets when it moves. A counter row, not a
  sequence: a sequence moves before the writer commits, so a reader could load the old
  data under the new version and never reload.
- ti_matcher_state: what each matcher instance has loaded, per tenant, for /health/detail.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = '7c1e9b2f4a60'
down_revision: Union[str, Sequence[str], None] = '14998d8588fb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"
TRIGGERS = {
    "iocs": "INSERT OR DELETE OR TRUNCATE OR UPDATE OF tenant_key, type, value, tlp, revoked, last_seen, valid_until",
    "ioc_sightings": "INSERT OR DELETE OR TRUNCATE OR UPDATE",
    "ti_allowlist": "INSERT OR DELETE OR TRUNCATE OR UPDATE",
    "ti_sources": "INSERT OR DELETE OR TRUNCATE OR UPDATE OF trust, enabled",
}


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("""
    CREATE TABLE incident_ti (
      id              bigserial PRIMARY KEY,
      tenant_key      varchar(64) NOT NULL REFERENCES tenants(tenant_key),
      node            varchar(255) NOT NULL,
      alert_id        varchar(255) NOT NULL,
      alert_time      timestamptz NOT NULL,
      rule_id         text NOT NULL,
      incident_id     integer NULL REFERENCES incidents(id),
      ioc_id          bigint NOT NULL REFERENCES iocs(id),
      field           text NOT NULL,          -- data.srcip, url.host, syscheck.sha256_after, ...
      observable_type text NOT NULL,
      observable      text NOT NULL,          -- the value seen in the alert (normalised)
      ioc_value       text NOT NULL,          -- the IOC it matched (a CIDR or parent domain may differ)
      sources         text[] NOT NULL,
      confidence      smallint NOT NULL,
      created_at      timestamptz NOT NULL DEFAULT now(),
      UNIQUE (tenant_key, node, alert_id, ioc_id)
    );
    CREATE INDEX incident_ti_incident ON incident_ti (incident_id);
    CREATE INDEX incident_ti_unlinked ON incident_ti (tenant_key, node, alert_id) WHERE incident_id IS NULL;

    ALTER TABLE incidents ADD COLUMN ti_confidence smallint NULL;
    ALTER TABLE incidents ADD COLUMN priority smallint GENERATED ALWAYS AS (GREATEST(max_level,
        CASE WHEN ti_confidence >= 75 THEN 12 WHEN ti_confidence >= 50 THEN 8 ELSE 0 END)) STORED;

    CREATE TABLE ti_store_version (
      id         boolean PRIMARY KEY DEFAULT true CHECK (id),
      version    bigint NOT NULL,
      changed_at timestamptz NOT NULL
    );
    INSERT INTO ti_store_version VALUES (true, 1, now());
    CREATE FUNCTION ti_store_version_bump() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      UPDATE ti_store_version SET version = version + 1, changed_at = now();
      RETURN NULL;
    END $$;

    CREATE TABLE ti_matcher_state (
      instance      text NOT NULL,
      tenant_key    text NOT NULL,
      store_version bigint NOT NULL,
      iocs          integer NOT NULL,
      by_type       jsonb NOT NULL,
      loaded_at     timestamptz NOT NULL,
      PRIMARY KEY (instance, tenant_key)
    );
    """))
    for table, events in TRIGGERS.items():
        conn.execute(text(f"CREATE TRIGGER {table}_store_version AFTER {events} ON {table} "
                          f"FOR EACH STATEMENT EXECUTE FUNCTION ti_store_version_bump()"))
    conn.execute(text(f"GRANT SELECT, INSERT, UPDATE ON incident_ti TO {APP_ROLE}"))
    conn.execute(text(f"GRANT USAGE, SELECT ON SEQUENCE incident_ti_id_seq TO {APP_ROLE}"))
    conn.execute(text(f"GRANT SELECT, UPDATE ON ti_store_version TO {APP_ROLE}"))
    conn.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ti_matcher_state TO {APP_ROLE}"))


def downgrade() -> None:
    conn = op.get_bind()
    for table in TRIGGERS:
        conn.execute(text(f"DROP TRIGGER {table}_store_version ON {table}"))
    conn.execute(text("DROP TABLE incident_ti, ti_store_version, ti_matcher_state; DROP FUNCTION ti_store_version_bump(); "
                      "ALTER TABLE incidents DROP COLUMN priority, DROP COLUMN ti_confidence"))
