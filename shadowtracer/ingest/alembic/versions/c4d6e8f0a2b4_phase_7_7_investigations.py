"""phase 7.7: LLM investigation results + per-tenant external-LLM opt-in

The analyst-triggered investigation agent stores one row per run (the full result pack, model name,
prompt version, latency, tokens, who, when) - tenant-scoped. This table is also the per-tenant daily
BUDGET source (count rows / sum tokens for today). The opt-in table gates whether a tenant may send
evidence to an EXTERNAL LLM provider; default is off, so everything uses the local Ollama model.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'c4d6e8f0a2b4'
down_revision: Union[str, Sequence[str], None] = 'b3c5d7e9f1a2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("""
    CREATE TABLE incident_investigations (
      id             bigserial PRIMARY KEY,
      tenant_key     varchar(64) NOT NULL REFERENCES tenants(tenant_key),
      incident_id    integer NOT NULL,
      result         jsonb NOT NULL,              -- sections, sentences(verified flags), evidence, tool_calls
      model          text NOT NULL,
      prompt_version text NOT NULL,
      latency_ms     integer NOT NULL,
      tokens         integer NOT NULL DEFAULT 0,
      created_by     text NOT NULL,               -- analyst email
      created_at     timestamptz NOT NULL DEFAULT now()
    )"""))
    conn.execute(text("CREATE INDEX ix_incident_investigations_incident "
                      "ON incident_investigations (tenant_key, incident_id, created_at DESC)"))
    conn.execute(text("CREATE INDEX ix_incident_investigations_budget "
                      "ON incident_investigations (tenant_key, created_at)"))
    conn.execute(text("""
    CREATE TABLE tenant_investigation_settings (
      tenant_key           varchar(64) PRIMARY KEY REFERENCES tenants(tenant_key),
      external_llm_enabled boolean NOT NULL DEFAULT false,   -- off: use the local model only
      updated_by           text,
      updated_at           timestamptz NOT NULL DEFAULT now()
    )"""))
    conn.execute(text(f"GRANT SELECT, INSERT ON incident_investigations TO {APP_ROLE}"))
    conn.execute(text(f"GRANT USAGE, SELECT ON SEQUENCE incident_investigations_id_seq TO {APP_ROLE}"))
    conn.execute(text(f"GRANT SELECT, INSERT, UPDATE ON tenant_investigation_settings TO {APP_ROLE}"))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("DROP TABLE IF EXISTS incident_investigations"))
    conn.execute(text("DROP TABLE IF EXISTS tenant_investigation_settings"))
