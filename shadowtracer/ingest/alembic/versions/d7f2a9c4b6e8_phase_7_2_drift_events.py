"""phase 7.2: River ADWIN behavioural + model-input drift events

Revision ID: d7f2a9c4b6e8
Revises: c6f1a3b5d7e9
Create Date: 2026-11-12

drift-monitor (own service, periodic, off the hot path, ClickHouse rollups only) runs one River
ADWIN per (entity, metric) and records a row here when a metric's distribution shifts. Advisory
only - no action, no retrain. entity_type 'agent' (behaviour drift per tenant+agent) or 'model'
(model-input drift per served model/feature). before/after are the ADWIN window means around the
change; window_start is when the change happened (the drifting bucket's hour).
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'd7f2a9c4b6e8'
down_revision: Union[str, Sequence[str], None] = 'c6f1a3b5d7e9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("""
    CREATE TABLE drift_events (
      id            bigserial PRIMARY KEY,
      tenant_key    varchar(64) NOT NULL,
      entity_type   text        NOT NULL CHECK (entity_type IN ('agent','model')),
      entity        text        NOT NULL,                 -- agent_id, or feature_version:feature
      metric        text        NOT NULL,                 -- alert_volume / distinct_rule_ids / ...
      window_start  timestamptz NOT NULL,                 -- the bucket where the change was detected
      before_value  double precision NOT NULL,
      after_value   double precision NOT NULL,
      magnitude     double precision NOT NULL,            -- |after - before|
      detected_at   timestamptz NOT NULL DEFAULT now(),
      UNIQUE (tenant_key, entity_type, entity, metric, window_start)
    )"""))
    conn.execute(text("CREATE INDEX drift_events_agent ON drift_events (tenant_key, entity_type, entity, window_start DESC)"))
    conn.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON drift_events TO {APP_ROLE}"))
    conn.execute(text(f"GRANT USAGE, SELECT ON SEQUENCE drift_events_id_seq TO {APP_ROLE}"))


def downgrade() -> None:
    op.get_bind().execute(text("DROP TABLE drift_events"))
