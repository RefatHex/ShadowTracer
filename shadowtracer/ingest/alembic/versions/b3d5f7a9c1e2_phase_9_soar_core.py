"""phase 9: SOAR core — action records, per-tenant + global safety state, worker cursor

Commit (a): the containment pipeline's storage. One row per intended/taken action in
soar_actions (idempotent on tenant+incident+playbook+action+target); per-tenant and
global kill switch + circuit-breaker + limits in soar_tenant_settings / soar_global_settings;
the enrichment worker's poll watermark in soar_worker_state. Playbooks, approvals, metrics
and notifier config arrive in later Phase 9 commits.

Nothing here touches the hot path; the SOAR worker reads these tables and incidents only.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'b3d5f7a9c1e2'
down_revision: Union[str, Sequence[str], None] = 'f8b2d4e6a0c1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    conn = op.get_bind()

    conn.execute(text("""
    CREATE TABLE soar_global_settings (
      id          smallint PRIMARY KEY DEFAULT 1,
      kill_switch boolean NOT NULL DEFAULT false,
      updated_at  timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT soar_global_settings_singleton CHECK (id = 1)
    )"""))
    conn.execute(text("INSERT INTO soar_global_settings (id) VALUES (1)"))

    conn.execute(text("""
    CREATE TABLE soar_tenant_settings (
      tenant_key              varchar(64) PRIMARY KEY REFERENCES tenants(tenant_key),
      kill_switch             boolean NOT NULL DEFAULT false,
      circuit_breaker_tripped boolean NOT NULL DEFAULT false,
      circuit_breaker_reason  text,
      circuit_breaker_tripped_at timestamptz,
      block_default_seconds   integer NOT NULL DEFAULT 3600,    -- default block 1 h
      block_max_seconds       integer NOT NULL DEFAULT 86400,   -- admin ceiling 24 h
      rate_limit_per_hour     integer NOT NULL DEFAULT 10,      -- containment actions / tenant / hour
      scope_limit_per_run     integer NOT NULL DEFAULT 5,       -- max targets one playbook run may act on
      updated_at              timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT soar_tenant_settings_block_bounds CHECK (block_default_seconds BETWEEN 1 AND block_max_seconds)
    )"""))

    # Admin-managed allowlist CIDRs (RFC1918/loopback/link-local are refused in code; this is the
    # "admin critical assets" + extra internal ranges list). agents'/manager IPs are added at runtime.
    conn.execute(text("""
    CREATE TABLE soar_allowlist (
      id         bigserial PRIMARY KEY,
      tenant_key varchar(64) NOT NULL REFERENCES tenants(tenant_key),
      cidr       text NOT NULL,
      note       text,
      created_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT soar_allowlist_identity UNIQUE (tenant_key, cidr)
    )"""))

    conn.execute(text("""
    CREATE TABLE soar_actions (
      id            bigserial PRIMARY KEY,
      tenant_key    varchar(64) NOT NULL REFERENCES tenants(tenant_key),
      incident_id   integer NOT NULL REFERENCES incidents(id),
      playbook_key  text NOT NULL,                 -- built-in trigger name until Phase 9 (e) playbooks
      action_type   text NOT NULL,                 -- block_ip | disable_account | quarantine_file | collect_evidence | notify | enrich
      target        text NOT NULL,                 -- ip / account / file path
      agent_id      text,                          -- agent the action runs on
      mode          text NOT NULL,                 -- shadow | approval | auto
      status        text NOT NULL,                 -- shadow | requested | approved | executed | undone | expired | refused | failed
      signals       jsonb NOT NULL DEFAULT '[]',   -- independent signals that satisfied the confidence gate
      refuse_reason text,                          -- set when status='refused'
      block_seconds integer,                        -- timed block duration (never NULL for an executed block)
      block_expires_at timestamptz,
      reason        text,                           -- approver reason (Phase 9 c)
      requested_by  text,
      approved_by   text,
      executed_by   text,
      error         text,                           -- set when status='failed'
      created_at    timestamptz NOT NULL DEFAULT now(),
      updated_at    timestamptz NOT NULL DEFAULT now(),
      executed_at   timestamptz,
      undone_at     timestamptz,
      expired_at    timestamptz,
      CONSTRAINT soar_actions_mode_check CHECK (mode IN ('shadow','approval','auto')),
      CONSTRAINT soar_actions_status_check CHECK (status IN
        ('shadow','requested','approved','executed','undone','expired','refused','failed')),
      CONSTRAINT soar_actions_idempotent UNIQUE (tenant_key, incident_id, playbook_key, action_type, target)
    )"""))
    conn.execute(text("CREATE INDEX ix_soar_actions_tenant_created ON soar_actions (tenant_key, created_at)"))
    conn.execute(text("CREATE INDEX ix_soar_actions_expiry ON soar_actions (status, block_expires_at) "
                      "WHERE status = 'executed'"))

    conn.execute(text("""
    CREATE TABLE soar_worker_state (
      id                smallint PRIMARY KEY DEFAULT 1,
      cursor_updated_at timestamptz NOT NULL DEFAULT 'epoch',
      cursor_id         bigint NOT NULL DEFAULT 0,
      updated_at        timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT soar_worker_state_singleton CHECK (id = 1)
    )"""))
    conn.execute(text("INSERT INTO soar_worker_state (id) VALUES (1)"))

    for tbl in ("soar_global_settings", "soar_tenant_settings", "soar_allowlist",
                "soar_actions", "soar_worker_state"):
        conn.execute(text(f"GRANT SELECT, INSERT, UPDATE ON {tbl} TO {APP_ROLE}"))
    conn.execute(text(f"GRANT USAGE, SELECT ON SEQUENCE soar_allowlist_id_seq TO {APP_ROLE}"))
    conn.execute(text(f"GRANT USAGE, SELECT ON SEQUENCE soar_actions_id_seq TO {APP_ROLE}"))


def downgrade() -> None:
    conn = op.get_bind()
    for tbl in ("soar_actions", "soar_allowlist", "soar_worker_state",
                "soar_tenant_settings", "soar_global_settings"):
        conn.execute(text(f"DROP TABLE IF EXISTS {tbl} CASCADE"))
