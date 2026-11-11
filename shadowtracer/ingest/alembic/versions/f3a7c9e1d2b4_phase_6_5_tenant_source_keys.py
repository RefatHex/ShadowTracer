"""phase 6.5 B: tenant-managed paid-source API keys (envelope-encrypted)

Revision ID: f3a7c9e1d2b4
Revises: e2c5a7d9b0f3
Create Date: 2026-11-12

One row per (tenant, paid source). The API key is stored only as an envelope-encrypted
blob (app/secrets_crypto.py): a per-key data key encrypts the secret, wrapped under the
deployment KEK that never touches the DB. The console writes keys write-only (it never
reads sealed_key back; it shows only key_fingerprint/key_last4); the intel worker reads
sealed_key to make the outbound call. enabled is the per-source opt-in; daily_budget and
cache_ttl_hours are per-tenant overrides of the source defaults; cooldown_until backs off
a source that returned 429.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'f3a7c9e1d2b4'
down_revision: Union[str, Sequence[str], None] = 'e2c5a7d9b0f3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"
SOURCES = "'virustotal','malwarebazaar','abuseipdb','greynoise'"


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text(f"""
    CREATE TABLE tenant_source_keys (
      tenant_key      varchar(64) NOT NULL REFERENCES tenants(tenant_key) ON DELETE CASCADE,
      source          text        NOT NULL CHECK (source IN ({SOURCES})),
      enabled         boolean     NOT NULL DEFAULT false,
      sealed_key      text,                       -- envelope blob; never returned to the console
      key_fingerprint text,                       -- sha256 prefix of the key value (non-secret)
      key_last4       text,
      key_version     integer     NOT NULL DEFAULT 0,
      daily_budget    integer,                    -- NULL = use the source default
      cache_ttl_hours integer,
      cooldown_until  timestamptz,                -- set when the source returns 429
      created_by      text,                       -- user who last set the key
      created_at      timestamptz NOT NULL DEFAULT now(),
      updated_at      timestamptz NOT NULL DEFAULT now(),
      rotated_at      timestamptz,
      PRIMARY KEY (tenant_key, source),
      -- a source can be enabled only once a key is present
      CONSTRAINT tenant_source_keys_enabled_needs_key CHECK (NOT enabled OR sealed_key IS NOT NULL),
      CONSTRAINT tenant_source_keys_budget_nonneg CHECK (daily_budget IS NULL OR daily_budget >= 0),
      CONSTRAINT tenant_source_keys_ttl_nonneg CHECK (cache_ttl_hours IS NULL OR cache_ttl_hours >= 0)
    )"""))
    conn.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_source_keys TO {APP_ROLE}"))


def downgrade() -> None:
    op.get_bind().execute(text("DROP TABLE tenant_source_keys"))
