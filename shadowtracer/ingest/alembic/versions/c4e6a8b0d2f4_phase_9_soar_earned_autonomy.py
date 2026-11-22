"""phase 9 (b): SOAR earned autonomy — per-playbook mode + promotion thresholds

soar_playbooks holds each playbook's current mode (shadow | approval | auto) and how it was last
switched. Every playbook starts in shadow; an admin may promote it to auto only once its shadow
precision clears the tenant's threshold over enough incidents (defaults 95% / 20, added to
soar_tenant_settings here). Phase 9 (c) EXTENDS soar_playbooks with the versioned YAML/steps.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'c4e6a8b0d2f4'
down_revision: Union[str, Sequence[str], None] = 'b3d5f7a9c1e2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("""
    CREATE TABLE soar_playbooks (
      tenant_key    varchar(64) NOT NULL REFERENCES tenants(tenant_key),
      playbook_key  text NOT NULL,
      mode          text NOT NULL DEFAULT 'shadow',
      promoted_at   timestamptz,
      promoted_by   text,
      promoted_from text,
      created_at    timestamptz NOT NULL DEFAULT now(),
      updated_at    timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (tenant_key, playbook_key),
      CONSTRAINT soar_playbooks_mode_check CHECK (mode IN ('shadow','approval','auto'))
    )"""))
    conn.execute(text("ALTER TABLE soar_tenant_settings "
                      "ADD COLUMN promotion_min_precision double precision NOT NULL DEFAULT 0.95, "
                      "ADD COLUMN promotion_min_incidents integer NOT NULL DEFAULT 20"))
    conn.execute(text(f"GRANT SELECT, INSERT, UPDATE ON soar_playbooks TO {APP_ROLE}"))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("DROP TABLE IF EXISTS soar_playbooks CASCADE"))
    conn.execute(text("ALTER TABLE soar_tenant_settings "
                      "DROP COLUMN IF EXISTS promotion_min_precision, "
                      "DROP COLUMN IF EXISTS promotion_min_incidents"))
