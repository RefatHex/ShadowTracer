"""phase 9 (c): SOAR playbooks (versioned) + approval TTL

Extends soar_playbooks with the admin-edited definition (trigger / required signals / steps with
per-step mode / block duration) as JSONB plus a version counter; soar_playbook_versions keeps every
prior version (append-only) for history/rollback. soar_tenant_settings gains approval_ttl_seconds:
an unanswered approval request older than this expires as "no action" (worker sweep).
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'd2f4a6c8e0b1'
down_revision: Union[str, Sequence[str], None] = 'c4e6a8b0d2f4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("ALTER TABLE soar_playbooks "
                      "ADD COLUMN definition jsonb, "
                      "ADD COLUMN version integer NOT NULL DEFAULT 1, "
                      "ADD COLUMN block_seconds integer, "
                      "ADD COLUMN updated_by text"))
    conn.execute(text("""
    CREATE TABLE soar_playbook_versions (
      tenant_key   varchar(64) NOT NULL REFERENCES tenants(tenant_key),
      playbook_key text NOT NULL,
      version      integer NOT NULL,
      definition   jsonb NOT NULL,
      created_by   text,
      created_at   timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (tenant_key, playbook_key, version)
    )"""))
    conn.execute(text("ALTER TABLE soar_tenant_settings "
                      "ADD COLUMN approval_ttl_seconds integer NOT NULL DEFAULT 3600"))
    conn.execute(text(f"GRANT SELECT, INSERT, UPDATE ON soar_playbook_versions TO {APP_ROLE}"))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("DROP TABLE IF EXISTS soar_playbook_versions"))
    conn.execute(text("ALTER TABLE soar_playbooks "
                      "DROP COLUMN IF EXISTS definition, DROP COLUMN IF EXISTS version, "
                      "DROP COLUMN IF EXISTS block_seconds, DROP COLUMN IF EXISTS updated_by"))
    conn.execute(text("ALTER TABLE soar_tenant_settings DROP COLUMN IF EXISTS approval_ttl_seconds"))
