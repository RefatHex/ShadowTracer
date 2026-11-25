"""phase 9 follow-up A: SOAR asset automation levels + repeat-offender escalation config

soar_asset_levels: admin-set automation level (full|approval|none) per agent or per role_tag; the
worker resolves agent -> role_tag -> default 'approval'. 'none' is never contained. soar_tenant_settings
gains the repeat-offender look-back window and the escalating block schedule (SOAR owns this; Wazuh's
repeated_offenders does not apply to API-dispatched custom scripts).
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'f3b5d7a9c1e4'
down_revision: Union[str, Sequence[str], None] = 'e1a3c5b7d9f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("""
    CREATE TABLE soar_asset_levels (
      tenant_key varchar(64) NOT NULL REFERENCES tenants(tenant_key),
      scope_type text NOT NULL,                 -- 'agent' | 'role_tag'
      scope_value text NOT NULL,                -- agent_id or role_tag
      level      text NOT NULL,                 -- 'full' | 'approval' | 'none'
      updated_by text,
      updated_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (tenant_key, scope_type, scope_value),
      CONSTRAINT soar_asset_levels_scope_check CHECK (scope_type IN ('agent','role_tag')),
      CONSTRAINT soar_asset_levels_level_check CHECK (level IN ('full','approval','none'))
    )"""))
    conn.execute(text("ALTER TABLE soar_tenant_settings "
                      "ADD COLUMN repeat_window_seconds integer NOT NULL DEFAULT 86400, "
                      "ADD COLUMN escalation_schedule integer[] NOT NULL DEFAULT '{3600,21600,86400}'"))
    conn.execute(text(f"GRANT SELECT, INSERT, UPDATE ON soar_asset_levels TO {APP_ROLE}"))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("DROP TABLE IF EXISTS soar_asset_levels"))
    conn.execute(text("ALTER TABLE soar_tenant_settings "
                      "DROP COLUMN IF EXISTS repeat_window_seconds, "
                      "DROP COLUMN IF EXISTS escalation_schedule"))
