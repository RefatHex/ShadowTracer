"""phase 6.3: VirusTotal - per-tenant opt-in, verdict cache, request queue, call log

Revision ID: b7e2c4d91f03
Revises: a3d5f0c2b8e1
Create Date: 2026-11-06

shadowtracer/docs/design/THREAT_INTEL.md §1.8, §3.4.
- ti_tenant_settings: VirusTotal is opt-in per tenant (default off) with a daily budget.
- vt_verdicts: one cached verdict per (tenant, SHA-256) until expires_at (7 days
  clean/unknown, 30 days malicious). Per tenant: each tenant looks up with its own key.
- vt_requests: every FIM alert or analyst request for a hash; a hash with a pending
  request and no fresh verdict is the queue.
- vt_calls: every call made to VirusTotal (budget accounting and audit), by key
  fingerprint, never the key.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'b7e2c4d91f03'
down_revision: Union[str, Sequence[str], None] = 'a3d5f0c2b8e1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("""
    CREATE TABLE ti_tenant_settings (
      tenant_key      varchar(64) PRIMARY KEY REFERENCES tenants(tenant_key),
      vt_enabled      boolean NOT NULL DEFAULT false,
      vt_daily_budget integer NOT NULL DEFAULT 500 CHECK (vt_daily_budget >= 0),
      updated_at      timestamptz NOT NULL DEFAULT now(),
      updated_by      text NOT NULL
    );
    CREATE TABLE vt_verdicts (
      tenant_key       varchar(64) NOT NULL REFERENCES tenants(tenant_key),
      sha256           char(64) NOT NULL,
      status           text NOT NULL CHECK (status IN ('malicious', 'clean', 'unknown')),
      malicious        integer NOT NULL DEFAULT 0,
      suspicious       integer NOT NULL DEFAULT 0,
      total            integer NOT NULL DEFAULT 0,
      labels           text[] NOT NULL DEFAULT '{}',
      first_submission timestamptz,
      last_analysis    timestamptz,
      permalink        text NOT NULL,
      fetched_at       timestamptz NOT NULL,
      expires_at       timestamptz NOT NULL,
      PRIMARY KEY (tenant_key, sha256)
    );
    CREATE TABLE vt_requests (
      id           bigserial PRIMARY KEY,
      tenant_key   varchar(64) NOT NULL REFERENCES tenants(tenant_key),
      sha256       char(64) NOT NULL,
      origin       text NOT NULL CHECK (origin IN ('fim', 'api')),
      node         text, alert_id text, alert_time timestamptz, rule_id text,
      agent_id     text, agent_name text, agent_ip text,
      path         text, md5 text, sha1 text,
      requested_by text,
      requested_at timestamptz NOT NULL DEFAULT now(),
      state        text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'resolved')),
      resolved_at  timestamptz,
      served_from  text CHECK (served_from IN ('cache', 'api')),
      delivered_at timestamptz
    );
    CREATE UNIQUE INDEX vt_requests_fim_alert ON vt_requests (tenant_key, node, alert_id, sha256) WHERE origin = 'fim';
    CREATE INDEX vt_requests_pending ON vt_requests (tenant_key, requested_at) WHERE state = 'pending';
    CREATE TABLE vt_calls (
      id          bigserial PRIMARY KEY,
      key_fp      text NOT NULL,
      tenant_key  varchar(64) NOT NULL,
      sha256      char(64) NOT NULL,
      called_at   timestamptz NOT NULL DEFAULT now(),
      http_status integer,
      outcome     text NOT NULL
    );
    CREATE INDEX vt_calls_key_time ON vt_calls (key_fp, called_at);
    CREATE INDEX vt_calls_tenant_time ON vt_calls (tenant_key, called_at);
    """))
    for t in ("ti_tenant_settings", "vt_verdicts", "vt_requests", "vt_calls"):
        conn.execute(text(f"GRANT SELECT, INSERT, UPDATE ON {t} TO {APP_ROLE}"))
    for seq in ("vt_requests_id_seq", "vt_calls_id_seq"):
        conn.execute(text(f"GRANT USAGE, SELECT ON SEQUENCE {seq} TO {APP_ROLE}"))


def downgrade() -> None:
    op.get_bind().execute(text("DROP TABLE vt_calls, vt_requests, vt_verdicts, ti_tenant_settings"))
