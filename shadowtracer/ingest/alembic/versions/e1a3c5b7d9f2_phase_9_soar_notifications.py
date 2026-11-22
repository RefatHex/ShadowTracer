"""phase 9 (e): SOAR notifications — per-tenant channel config + delivery queue

soar_channels: each tenant/channel's config (enabled off by default, detail level minimal|standard,
severity threshold, throttle + batch window). Secrets are NEVER stored here — they come from the
environment; the API only ever reports configured/not-configured.
soar_notifications: the delivery queue (queued -> sent|failed) with attempts, backoff and a 429
retry-after honour time. Delivery failures live here, visible in settings, and never block an action.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'e1a3c5b7d9f2'
down_revision: Union[str, Sequence[str], None] = 'd2f4a6c8e0b1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("""
    CREATE TABLE soar_channels (
      tenant_key     varchar(64) NOT NULL REFERENCES tenants(tenant_key),
      channel        text NOT NULL,
      enabled        boolean NOT NULL DEFAULT false,
      detail_level   text NOT NULL DEFAULT 'minimal',
      min_severity   integer NOT NULL DEFAULT 0,
      throttle_seconds integer NOT NULL DEFAULT 0,
      batch_window_seconds integer NOT NULL DEFAULT 60,
      updated_by     text,
      created_at     timestamptz NOT NULL DEFAULT now(),
      updated_at     timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (tenant_key, channel),
      CONSTRAINT soar_channels_channel_check CHECK
        (channel IN ('email','webhook','slack','discord','telegram','shuffle')),
      CONSTRAINT soar_channels_detail_check CHECK (detail_level IN ('minimal','standard'))
    )"""))
    conn.execute(text("""
    CREATE TABLE soar_notifications (
      id            bigserial PRIMARY KEY,
      tenant_key    varchar(64) NOT NULL REFERENCES tenants(tenant_key),
      channel       text NOT NULL,
      event         text NOT NULL,
      severity      integer NOT NULL DEFAULT 0,
      context       jsonb NOT NULL DEFAULT '{}',
      status        text NOT NULL DEFAULT 'queued',
      attempts      integer NOT NULL DEFAULT 0,
      next_attempt_at timestamptz NOT NULL DEFAULT now(),
      retry_after_until timestamptz,
      last_error    text,
      created_at    timestamptz NOT NULL DEFAULT now(),
      sent_at       timestamptz,
      CONSTRAINT soar_notifications_status_check CHECK (status IN ('queued','sent','failed'))
    )"""))
    conn.execute(text("CREATE INDEX ix_soar_notifications_due ON soar_notifications "
                      "(status, next_attempt_at) WHERE status = 'queued'"))
    for t in ("soar_channels", "soar_notifications"):
        conn.execute(text(f"GRANT SELECT, INSERT, UPDATE ON {t} TO {APP_ROLE}"))
    conn.execute(text(f"GRANT USAGE, SELECT ON SEQUENCE soar_notifications_id_seq TO {APP_ROLE}"))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("DROP TABLE IF EXISTS soar_notifications"))
    conn.execute(text("DROP TABLE IF EXISTS soar_channels"))
