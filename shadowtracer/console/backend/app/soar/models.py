"""SOAR Core table definitions (mirror ingest/alembic b3d5f7a9c1e2). Reuses the console
metadata so the console API and the worker share one table registry."""

from sqlalchemy import (
    BigInteger, Boolean, CheckConstraint, Column, DateTime, Float, ForeignKey, Integer,
    SmallInteger, String, Table, Text, UniqueConstraint, func,
)
from sqlalchemy.dialects.postgresql import JSONB

from ..models import metadata

soar_global_settings = Table(
    "soar_global_settings", metadata,
    Column("id", SmallInteger, primary_key=True),
    Column("kill_switch", Boolean, nullable=False, server_default="false"),
    Column("updated_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
)

soar_tenant_settings = Table(
    "soar_tenant_settings", metadata,
    Column("tenant_key", String(64), ForeignKey("tenants.tenant_key"), primary_key=True),
    Column("kill_switch", Boolean, nullable=False, server_default="false"),
    Column("circuit_breaker_tripped", Boolean, nullable=False, server_default="false"),
    Column("circuit_breaker_reason", Text, nullable=True),
    Column("circuit_breaker_tripped_at", DateTime(timezone=True), nullable=True),
    Column("block_default_seconds", Integer, nullable=False, server_default="3600"),
    Column("block_max_seconds", Integer, nullable=False, server_default="86400"),
    Column("rate_limit_per_hour", Integer, nullable=False, server_default="10"),
    Column("scope_limit_per_run", Integer, nullable=False, server_default="5"),
    # Phase 9 (b): earned-autonomy promotion gate (shadow -> auto).
    Column("promotion_min_precision", Float, nullable=False, server_default="0.95"),
    Column("promotion_min_incidents", Integer, nullable=False, server_default="20"),
    # Phase 9 (c): unanswered approval request TTL (then expires as no-action).
    Column("approval_ttl_seconds", Integer, nullable=False, server_default="3600"),
    Column("updated_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
)

# Phase 9 (b)+(c): per-playbook mode + promotion audit, plus the admin-edited versioned definition.
soar_playbooks = Table(
    "soar_playbooks", metadata,
    Column("tenant_key", String(64), ForeignKey("tenants.tenant_key"), primary_key=True),
    Column("playbook_key", Text, primary_key=True),
    Column("mode", Text, nullable=False, server_default="shadow"),
    Column("promoted_at", DateTime(timezone=True), nullable=True),
    Column("promoted_by", Text, nullable=True),
    Column("promoted_from", Text, nullable=True),
    Column("definition", JSONB, nullable=True),            # trigger / required signals / steps / duration
    Column("version", Integer, nullable=False, server_default="1"),
    Column("block_seconds", Integer, nullable=True),        # per-playbook block duration override
    Column("updated_by", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    Column("updated_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    CheckConstraint("mode IN ('shadow','approval','auto')", name="soar_playbooks_mode_check"),
)

soar_playbook_versions = Table(
    "soar_playbook_versions", metadata,
    Column("tenant_key", String(64), ForeignKey("tenants.tenant_key"), primary_key=True),
    Column("playbook_key", Text, primary_key=True),
    Column("version", Integer, primary_key=True),
    Column("definition", JSONB, nullable=False),
    Column("created_by", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
)

# Phase 9 (e): per-tenant notification channel config. Secrets are NOT here (env only).
soar_channels = Table(
    "soar_channels", metadata,
    Column("tenant_key", String(64), ForeignKey("tenants.tenant_key"), primary_key=True),
    Column("channel", Text, primary_key=True),
    Column("enabled", Boolean, nullable=False, server_default="false"),
    Column("detail_level", Text, nullable=False, server_default="minimal"),
    Column("min_severity", Integer, nullable=False, server_default="0"),
    Column("throttle_seconds", Integer, nullable=False, server_default="0"),
    Column("batch_window_seconds", Integer, nullable=False, server_default="60"),
    Column("updated_by", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    Column("updated_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    CheckConstraint("channel IN ('email','webhook','slack','discord','telegram','shuffle')",
                    name="soar_channels_channel_check"),
    CheckConstraint("detail_level IN ('minimal','standard')", name="soar_channels_detail_check"),
)

soar_notifications = Table(
    "soar_notifications", metadata,
    Column("id", BigInteger, primary_key=True),
    Column("tenant_key", String(64), ForeignKey("tenants.tenant_key"), nullable=False),
    Column("channel", Text, nullable=False),
    Column("event", Text, nullable=False),
    Column("severity", Integer, nullable=False, server_default="0"),
    Column("context", JSONB, nullable=False, server_default="{}"),
    Column("status", Text, nullable=False, server_default="queued"),
    Column("attempts", Integer, nullable=False, server_default="0"),
    Column("next_attempt_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    Column("retry_after_until", DateTime(timezone=True), nullable=True),
    Column("last_error", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    Column("sent_at", DateTime(timezone=True), nullable=True),
    CheckConstraint("status IN ('queued','sent','failed')", name="soar_notifications_status_check"),
)

soar_allowlist = Table(
    "soar_allowlist", metadata,
    Column("id", BigInteger, primary_key=True),
    Column("tenant_key", String(64), ForeignKey("tenants.tenant_key"), nullable=False),
    Column("cidr", Text, nullable=False),
    Column("note", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    UniqueConstraint("tenant_key", "cidr", name="soar_allowlist_identity"),
)

soar_actions = Table(
    "soar_actions", metadata,
    Column("id", BigInteger, primary_key=True),
    Column("tenant_key", String(64), ForeignKey("tenants.tenant_key"), nullable=False),
    Column("incident_id", Integer, ForeignKey("incidents.id"), nullable=False),
    Column("playbook_key", Text, nullable=False),
    Column("action_type", Text, nullable=False),
    Column("target", Text, nullable=False),
    Column("agent_id", Text, nullable=True),
    Column("mode", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("signals", JSONB, nullable=False, server_default="[]"),
    Column("refuse_reason", Text, nullable=True),
    Column("block_seconds", Integer, nullable=True),
    Column("block_expires_at", DateTime(timezone=True), nullable=True),
    Column("reason", Text, nullable=True),
    Column("requested_by", Text, nullable=True),
    Column("approved_by", Text, nullable=True),
    Column("executed_by", Text, nullable=True),
    Column("error", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    Column("updated_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    Column("executed_at", DateTime(timezone=True), nullable=True),
    Column("undone_at", DateTime(timezone=True), nullable=True),
    Column("expired_at", DateTime(timezone=True), nullable=True),
    CheckConstraint("mode IN ('shadow','approval','auto')", name="soar_actions_mode_check"),
    CheckConstraint(
        "status IN ('shadow','requested','approved','executed','undone','expired','refused','failed')",
        name="soar_actions_status_check"),
    UniqueConstraint("tenant_key", "incident_id", "playbook_key", "action_type", "target",
                     name="soar_actions_idempotent"),
)

soar_worker_state = Table(
    "soar_worker_state", metadata,
    Column("id", SmallInteger, primary_key=True),
    Column("cursor_updated_at", DateTime(timezone=True), nullable=False),
    Column("cursor_id", BigInteger, nullable=False),
    Column("updated_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
)
