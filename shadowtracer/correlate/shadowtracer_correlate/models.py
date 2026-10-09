"""SQLAlchemy Core table definitions mirroring the Alembic migration
shadowtracer/ingest/alembic/versions/cfe022c4de55_phase_5a_incidents_and_incident_alerts.py
(the single source of truth for the schema - these must stay in sync
with it by hand, same as shadowtracer/console/backend/app/models.py does
for the auth tables)."""

from sqlalchemy import (
    Boolean, CheckConstraint, Column, DateTime, ForeignKey, ForeignKeyConstraint,
    Integer, MetaData, SmallInteger, String, Table, Text, UniqueConstraint, func, text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

metadata = MetaData()

# Stub, not the real definition (that's shadowtracer/console/backend/app/
# models.py's tenants, owned by the backend's auth tables) - just enough
# columns for the tenant_key FKs below to resolve within this file's own
# MetaData. This process never creates/alters/reads this table directly.
tenants = Table(
    "tenants", metadata,
    Column("id", Integer, primary_key=True),
    Column("tenant_key", String(64), nullable=False, unique=True),
)

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
    Column("rare_pattern_flag", Boolean, nullable=False, server_default=text("false")),
    Column("prior_occurrences", Integer, nullable=True),
    Column("rare_pattern_reason", Text, nullable=True),
    CheckConstraint("state IN ('open', 'closed')", name="incidents_state_check"),
    CheckConstraint(
        "triage_status IN ('new', 'acknowledged', 'escalated', 'false_positive', 'closed')",
        name="incidents_triage_status_check",
    ),
    CheckConstraint(
        "correlation_basis IN ('source_ip', 'user', 'rule_group')",
        name="incidents_correlation_basis_check",
    ),
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
    CheckConstraint(
        "suppression_state IN ('none', 'proposed', 'active')",
        name="fingerprints_suppression_state_check",
    ),
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
    CheckConstraint(
        "verdict IN ('acknowledged', 'escalated', 'false_positive')",
        name="fingerprint_verdicts_verdict_check",
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
    Column("rare_alert_prior_occurrence_threshold", Integer, nullable=False, server_default="0"),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    Column("updated_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
)

sequence_progress = Table(
    "sequence_progress", metadata,
    Column("id", Integer, primary_key=True),
    Column("tenant_key", String(64), ForeignKey("tenants.tenant_key"), nullable=False),
    Column("sequence_id", String(100), nullable=False),
    Column("agent_id", String(255), nullable=False),
    Column("key_type", String(20), nullable=False),
    Column("key_value", String(255), nullable=False),
    Column("current_step", Integer, nullable=False, server_default="0"),
    Column("first_step_at", DateTime(timezone=True), nullable=False),
    Column("last_step_at", DateTime(timezone=True), nullable=False),
    Column("step_matches", JSONB, nullable=False, server_default="[]"),
    Column("updated_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    UniqueConstraint(
        "tenant_key", "sequence_id", "agent_id", "key_type", "key_value",
        name="sequence_progress_identity_unique",
    ),
    CheckConstraint("key_type IN ('source_ip', 'user')", name="sequence_progress_key_type_check"),
)

campaigns = Table(
    "campaigns", metadata,
    Column("id", Integer, primary_key=True),
    Column("tenant_key", String(64), ForeignKey("tenants.tenant_key"), nullable=False),
    Column("fingerprint_key", String(64), nullable=False),
    Column("actor_type", String(20), nullable=False),
    Column("actor_value", String(255), nullable=False),
    Column("first_seen", DateTime(timezone=True), nullable=False),
    Column("last_seen", DateTime(timezone=True), nullable=False),
    Column("incident_count", Integer, nullable=False, server_default="0"),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    Column("updated_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    CheckConstraint("actor_type IN ('source_ip', 'user')", name="campaigns_actor_type_check"),
)

campaign_incidents = Table(
    "campaign_incidents", metadata,
    Column("id", Integer, primary_key=True),
    Column("campaign_id", Integer, ForeignKey("campaigns.id"), nullable=False),
    Column("incident_id", Integer, ForeignKey("incidents.id"), nullable=False),
    Column("tenant_key", String(64), ForeignKey("tenants.tenant_key"), nullable=False),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    UniqueConstraint("campaign_id", "incident_id", name="campaign_incidents_identity_unique"),
)
