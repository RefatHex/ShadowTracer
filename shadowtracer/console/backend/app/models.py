"""SQLAlchemy Core table definitions mirroring the Alembic migrations in
shadowtracer/ingest/alembic/versions/. Core, not the ORM - these are
simple CRUD tables with no object-graph navigation worth the ORM's
session-identity-map complexity."""

from sqlalchemy import (
    Boolean, CheckConstraint, Column, DateTime, ForeignKey, ForeignKeyConstraint,
    Index, Integer, MetaData, PrimaryKeyConstraint, SmallInteger, String,
    Table, Text, UniqueConstraint, func, text,
)
from sqlalchemy.dialects.postgresql import ARRAY

metadata = MetaData()

tenants = Table(
    "tenants", metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String(255), nullable=False, unique=True),
    # Permanent identity, set once at creation and never exposed through
    # any update path - the shipper stamps events with this and the
    # access token carries it, so renaming `name` (display-only) can
    # never change which events a tenant sees.
    Column("tenant_key", String(64), nullable=False, unique=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
)

users = Table(
    "users", metadata,
    Column("id", Integer, primary_key=True),
    Column("tenant_id", Integer, ForeignKey("tenants.id"), nullable=False),
    Column("email", String(255), nullable=False),
    Column("password_hash", String(255), nullable=False),
    Column("role", String(20), nullable=False),
    Column("is_active", Boolean, nullable=False, server_default=text("true")),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
    CheckConstraint("role IN ('admin', 'analyst', 'viewer')", name="users_role_check"),
    UniqueConstraint("tenant_id", "email", name="users_tenant_email_unique"),
)

refresh_tokens = Table(
    "refresh_tokens", metadata,
    Column("id", Integer, primary_key=True),
    Column("family_id", String(36), nullable=False),
    Column("user_id", Integer, ForeignKey("users.id"), nullable=False),
    Column("token_hash", String(64), nullable=False, unique=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("used_at", DateTime(timezone=True), nullable=True),
    Column("family_revoked", Boolean, nullable=False, server_default=text("false")),
    Index("ix_refresh_tokens_family_id", "family_id"),
)

login_attempts = Table(
    "login_attempts", metadata,
    Column("id", Integer, primary_key=True),
    Column("ip", String(45), nullable=False),
    Column("email", String(255), nullable=True),
    Column("success", Boolean, nullable=False),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
    Index("ix_login_attempts_ip_created_at", "ip", "created_at"),
    Index("ix_login_attempts_email_created_at", "email", "created_at"),
)

audit_log = Table(
    "audit_log", metadata,
    Column("id", Integer, primary_key=True),
    Column("actor", String(255), nullable=False),
    Column("tenant_id", Integer, nullable=True),
    Column("action", String(100), nullable=False),
    Column("target", String(255), nullable=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
    Column("outcome", String(20), nullable=False),
    Column("prev_hash", String(64), nullable=False),
    Column("row_hash", String(64), nullable=False),
)

# Phase 5A: written by shadowtracer/correlate (a separate process/venv,
# which defines these same tables again in its own models.py - same
# precedent as this file already is for the ingest-written auth tables).
# Keyed by tenant_key (Phase 4 follow-up 1), not tenants.id - the
# correlator never sees the numeric id, only tenant_key from Kafka.
incidents = Table(
    "incidents", metadata,
    Column("id", Integer, primary_key=True),
    Column("tenant_key", String(64), ForeignKey("tenants.tenant_key"), nullable=False),
    Column("correlation_key", String(512), nullable=False),
    Column("correlation_basis", String(20), nullable=False),
    Column("agent_id", String(255), nullable=False),
    Column("first_seen", DateTime(timezone=True), nullable=False),
    Column("last_seen", DateTime(timezone=True), nullable=False),
    Column("alert_count", Integer, nullable=False, server_default="0"),
    Column("max_level", SmallInteger, nullable=False, server_default="0"),
    Column("rule_ids", ARRAY(String), nullable=False, server_default="{}"),
    Column("rule_groups", ARRAY(String), nullable=False, server_default="{}"),
    Column("mitre_ids", ARRAY(String), nullable=False, server_default="{}"),
    Column("source_ips", ARRAY(String), nullable=False, server_default="{}"),
    Column("source_ip_total", Integer, nullable=False, server_default="0"),
    Column("users", ARRAY(String), nullable=False, server_default="{}"),
    Column("user_total", Integer, nullable=False, server_default="0"),
    Column("state", String(10), nullable=False, server_default="open"),
    Column("triage_status", String(20), nullable=False, server_default="new"),
    Column("fingerprint_key", String(64), nullable=True),
    Column("ruleset_version", String(50), nullable=True),
    Column("closed_at", DateTime(timezone=True), nullable=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    Column("updated_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    # Phase 5B Step 3: a flag, never a replacement for the incident itself.
    Column("rare_pattern_flag", Boolean, nullable=False, server_default=text("false")),
    Column("prior_occurrences", Integer, nullable=True),
    Column("rare_pattern_reason", Text, nullable=True),
)

incident_alerts = Table(
    "incident_alerts", metadata,
    Column("id", Integer, primary_key=True),
    Column("incident_id", Integer, ForeignKey("incidents.id"), nullable=False),
    Column("tenant_key", String(64), ForeignKey("tenants.tenant_key"), nullable=False),
    Column("node", String(255), nullable=False),
    Column("alert_id", String(255), nullable=False),
    Column("alert_time", DateTime(timezone=True), nullable=False),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    UniqueConstraint("tenant_key", "node", "alert_id", name="incident_alerts_identity_unique"),
)

fingerprints = Table(
    "fingerprints", metadata,
    Column("tenant_key", String(64), ForeignKey("tenants.tenant_key"), primary_key=True),
    Column("fingerprint_key", String(64), primary_key=True),
    Column("label", String(255), nullable=True),
    Column("notes", Text, nullable=True),
    Column("suppression_state", String(20), nullable=False, server_default="none"),
    Column("suppression_expires_at", DateTime(timezone=True), nullable=True),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    Column("updated_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
)

fingerprint_verdicts = Table(
    "fingerprint_verdicts", metadata,
    Column("id", Integer, primary_key=True),
    Column("tenant_key", String(64), ForeignKey("tenants.tenant_key"), nullable=False),
    Column("fingerprint_key", String(64), nullable=False),
    Column("incident_id", Integer, ForeignKey("incidents.id"), nullable=False),
    Column("analyst_user_id", Integer, ForeignKey("users.id"), nullable=False),
    Column("verdict", String(20), nullable=False),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    ForeignKeyConstraint(
        ["tenant_key", "fingerprint_key"], ["fingerprints.tenant_key", "fingerprints.fingerprint_key"],
        name="fingerprint_verdicts_fingerprint_fkey",
    ),
)

agent_role_tags = Table(
    "agent_role_tags", metadata,
    Column("tenant_key", String(64), ForeignKey("tenants.tenant_key"), primary_key=True),
    Column("agent_id", String(255), primary_key=True),
    Column("role_tag", String(100), nullable=True),
    Column("os_family", String(50), nullable=True),
    Column("updated_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
)

tenant_alert_settings = Table(
    "tenant_alert_settings", metadata,
    Column("tenant_key", String(64), ForeignKey("tenants.tenant_key"), primary_key=True),
    Column("rare_alert_warmup_days", Integer, nullable=False, server_default="7"),
    Column("rare_alert_warmup_min_incidents", Integer, nullable=False, server_default="30"),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    Column("updated_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
)
