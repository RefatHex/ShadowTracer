"""phase 7.7 follow-up: async investigation status (running/ok/llm_unavailable/evidence_too_large/error)

The investigate endpoint now runs in the background so it never ties up a console worker for ~19 s.
A row is inserted as 'running' immediately; the background job updates it to its final status. A partial
unique index enforces "one running investigation per (tenant, incident)" atomically (replacing the old
transaction-scoped advisory lock, which could not span a background task). `result` becomes nullable
because a freshly-queued running row has no result yet.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'd7e9f1b3c5a6'
down_revision: Union[str, Sequence[str], None] = 'c4d6e8f0a2b4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("ALTER TABLE incident_investigations ALTER COLUMN result DROP NOT NULL"))
    conn.execute(text("ALTER TABLE incident_investigations ADD COLUMN status text NOT NULL DEFAULT 'ok'"))
    conn.execute(text("ALTER TABLE incident_investigations ADD COLUMN message text"))
    # one running investigation per (tenant, incident) at a time - enforced atomically
    conn.execute(text("CREATE UNIQUE INDEX uq_investigation_running ON incident_investigations "
                      "(tenant_key, incident_id) WHERE status = 'running'"))
    conn.execute(text(f"GRANT UPDATE ON incident_investigations TO {APP_ROLE}"))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("DROP INDEX IF EXISTS uq_investigation_running"))
    conn.execute(text("ALTER TABLE incident_investigations DROP COLUMN IF EXISTS status"))
    conn.execute(text("ALTER TABLE incident_investigations DROP COLUMN IF EXISTS message"))
