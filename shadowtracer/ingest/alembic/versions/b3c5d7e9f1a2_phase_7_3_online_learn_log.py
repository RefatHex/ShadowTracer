"""phase 7.3: online-model learn audit / rate-cap / rollback log

Revision ID: b3c5d7e9f1a2
Revises: a2b4c6d8e0f1
Create Date: 2026-11-21

The River ARF online model (incident-online) learns online from labelled incidents (analyst
verdicts + ART attack-window runs). Every learn_one is audited here: who (analyst), when, which
incident, what label, and which signed MLflow checkpoint it was folded into. This table is:
  - the AUDIT trail (analyst + time, per the spec),
  - the per-analyst-per-hour RATE CAP source (count rows for an analyst in the last hour),
  - the de-dup guard (learn each incident at most once; UNIQUE incident),
  - and the ROLLBACK ledger: rolling back to an earlier checkpoint flags the newer rows rolled_back
    so the reverted model never re-learns that bad batch.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'b3c5d7e9f1a2'
down_revision: Union[str, Sequence[str], None] = 'a2b4c6d8e0f1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("""
    CREATE TABLE online_learn_log (
      id                 bigserial PRIMARY KEY,
      tenant_key         varchar(64) NOT NULL REFERENCES tenants(tenant_key),
      incident_id        integer NOT NULL,
      label              text NOT NULL,
      origin             text NOT NULL,             -- analyst_verdict | attack_window
      analyst            text,                      -- analyst_verdict: the approving analyst (rate cap + audit); 'art' for attack_window
      checkpoint_version text,                      -- the MLflow incident-online version this learn was saved into
      rolled_back        boolean NOT NULL DEFAULT false,
      learned_at         timestamptz NOT NULL DEFAULT now(),
      UNIQUE (tenant_key, incident_id)
    )"""))
    conn.execute(text("CREATE INDEX ix_online_learn_log_analyst_time ON online_learn_log (analyst, learned_at)"))
    conn.execute(text(f"GRANT SELECT, INSERT, UPDATE ON online_learn_log TO {APP_ROLE}"))
    conn.execute(text(f"GRANT USAGE, SELECT ON SEQUENCE online_learn_log_id_seq TO {APP_ROLE}"))


def downgrade() -> None:
    op.get_bind().execute(text("DROP TABLE IF EXISTS online_learn_log"))
