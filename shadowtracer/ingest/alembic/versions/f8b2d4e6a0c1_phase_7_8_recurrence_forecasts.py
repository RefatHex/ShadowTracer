"""phase 7.8: attack recurrence forecasts per fingerprint and per campaign

One row per (tenant, subject_type, subject_key) holding the latest forecast: predicted next window,
probability, confidence, and the model inputs (event count, gap CV, hour-of-week profile). Written by
the ml-enricher's hourly job and recompute-on-view in the console; read tenant-scoped by analyst+.
Advisory/experimental - a hint, never an alert.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'f8b2d4e6a0c1'
down_revision: Union[str, Sequence[str], None] = 'd7e9f1b3c5a6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("""
    CREATE TABLE recurrence_forecasts (
      id             bigserial PRIMARY KEY,
      tenant_key     varchar(64) NOT NULL REFERENCES tenants(tenant_key),
      subject_type   text NOT NULL,              -- 'fingerprint' | 'campaign'
      subject_key    text NOT NULL,              -- fingerprint_key, or campaign id as text
      occurrences    integer NOT NULL,           -- distinct EVENTS (bursts collapsed)
      raw_occurrences integer NOT NULL,          -- underlying incident count
      predicted_start timestamptz NOT NULL,
      predicted_end   timestamptz NOT NULL,
      probability    double precision NOT NULL,
      confidence     text NOT NULL,              -- low | medium | high
      median_gap_seconds bigint,
      gap_cv         double precision,
      modal_hour_of_week integer,                -- 0=Mon 00:00 .. 167=Sun 23:00
      hour_of_week_concentration double precision,
      last_occurrence timestamptz NOT NULL,
      model_version  text NOT NULL,
      computed_at    timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT recurrence_forecasts_subject_type_check
        CHECK (subject_type IN ('fingerprint', 'campaign')),
      CONSTRAINT recurrence_forecasts_identity_unique
        UNIQUE (tenant_key, subject_type, subject_key)
    )"""))
    conn.execute(text("CREATE INDEX ix_recurrence_forecasts_lookup "
                      "ON recurrence_forecasts (tenant_key, subject_type, subject_key)"))
    conn.execute(text(f"GRANT SELECT, INSERT, UPDATE ON recurrence_forecasts TO {APP_ROLE}"))
    conn.execute(text(f"GRANT USAGE, SELECT ON SEQUENCE recurrence_forecasts_id_seq TO {APP_ROLE}"))


def downgrade() -> None:
    op.get_bind().execute(text("DROP TABLE IF EXISTS recurrence_forecasts"))
