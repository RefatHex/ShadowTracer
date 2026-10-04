"""phase 5a incidents, incident_alerts, fingerprints, fingerprint_verdicts, agent_role_tags

Revision ID: cfe022c4de55
Revises: 6cb09091c77c
Create Date: 2026-10-04 09:37:05.917680

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import ARRAY


# revision identifiers, used by Alembic.
revision: str = 'cfe022c4de55'
down_revision: Union[str, Sequence[str], None] = '6cb09091c77c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"

# incidents/incident_alerts/fingerprints/agent_role_tags are keyed by
# tenant_key (the permanent identity from Phase 4 follow-up 1), not
# Postgres's numeric tenants.id - the correlation engine and the API both
# only ever see tenant_key (from the Kafka event headers and the JWT,
# respectively), never the numeric id, so there is no natural join target
# and no reason to introduce one just to satisfy a foreign key.
NEW_TABLES = ("incidents", "incident_alerts", "fingerprints", "fingerprint_verdicts", "agent_role_tags")


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_key", sa.String(64), nullable=False),
        sa.Column("correlation_key", sa.String(512), nullable=False),
        sa.Column("correlation_basis", sa.String(20), nullable=False),
        sa.Column("agent_id", sa.String(255), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("alert_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("max_level", sa.SmallInteger, nullable=False, server_default="0"),
        sa.Column("rule_ids", ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("mitre_ids", ARRAY(sa.String), nullable=False, server_default="{}"),
        # Capped distinct values (Step 1): a fixed-size sample array plus
        # the real total count, so a scan of 10,000 source IPs can't grow
        # this row without bound - see shadowtracer/correlate/.
        sa.Column("source_ips", ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("source_ip_total", sa.Integer, nullable=False, server_default="0"),
        sa.Column("users", ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("user_total", sa.Integer, nullable=False, server_default="0"),
        sa.Column("state", sa.String(10), nullable=False, server_default="open"),
        sa.Column("triage_status", sa.String(20), nullable=False, server_default="new"),
        # Set only when the incident closes (Step 3) - the ruleset version
        # active at that moment, stored alongside the hash per spec.
        sa.Column("fingerprint_key", sa.String(64), nullable=True),
        sa.Column("ruleset_version", sa.String(50), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("state IN ('open', 'closed')", name="incidents_state_check"),
        sa.CheckConstraint(
            "triage_status IN ('new', 'acknowledged', 'escalated', 'false_positive', 'closed')",
            name="incidents_triage_status_check",
        ),
        sa.CheckConstraint(
            "correlation_basis IN ('source_ip', 'user', 'rule_group')",
            name="incidents_correlation_basis_check",
        ),
    )
    # The correlator's hot-path lookup: "which open incident(s) does this
    # tenant/agent currently have, to join this alert into one". Indexed
    # on exactly those columns plus state.
    op.create_index(
        "ix_incidents_open_lookup", "incidents",
        ["tenant_key", "agent_id", "state"],
    )
    op.create_index("ix_incidents_tenant_key", "incidents", ["tenant_key"])
    op.create_index("ix_incidents_fingerprint_key", "incidents", ["tenant_key", "fingerprint_key"])

    # Link table (Step 1/2): membership only, never alert content - the
    # real alert stays in ClickHouse, queryable there regardless of
    # incident state, per "incidents never delete or hide alerts".
    op.create_table(
        "incident_alerts",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("incident_id", sa.Integer, sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("tenant_key", sa.String(64), nullable=False),
        sa.Column("node", sa.String(255), nullable=False),
        sa.Column("alert_id", sa.String(255), nullable=False),
        sa.Column("alert_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        # The idempotency key (Step 1): replaying Kafka re-processes the
        # same alert, and this is what turns the second attempt into a
        # no-op (ON CONFLICT DO NOTHING) instead of a duplicate row or a
        # double-counted incident.
        sa.UniqueConstraint("tenant_key", "node", "alert_id", name="incident_alerts_identity_unique"),
    )
    op.create_index("ix_incident_alerts_incident_id", "incident_alerts", ["incident_id"])

    # Fingerprints are tenant-scoped (Step 3/4): the hash VALUE never
    # includes tenant-identifying data, so the same attack shape in two
    # different tenants hashes identically, but every other part of this
    # project enforces hard tenant isolation (RBAC, ClickHouse queries,
    # audit log) - sharing occurrence counts/verdicts/suppression across
    # tenants would leak "tenant A was attacked" to tenant B. Composite
    # key keeps the Attack Library isolated the same way everything else
    # is, at the cost of not pooling pattern-recognition across tenants -
    # see DECISIONS.md.
    op.create_table(
        "fingerprints",
        sa.Column("tenant_key", sa.String(64), nullable=False),
        sa.Column("fingerprint_key", sa.String(64), nullable=False),
        sa.Column("label", sa.String(255), nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("suppression_state", sa.String(20), nullable=False, server_default="none"),
        sa.Column("suppression_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("tenant_key", "fingerprint_key"),
        sa.CheckConstraint(
            "suppression_state IN ('none', 'proposed', 'active')",
            name="fingerprints_suppression_state_check",
        ),
    )

    # One row per triage verdict that counts toward suppression (Step 4) -
    # a plain counter column couldn't enforce "5+ verdicts from 2+
    # DIFFERENT analysts", which needs COUNT(DISTINCT analyst_user_id).
    op.create_table(
        "fingerprint_verdicts",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_key", sa.String(64), nullable=False),
        sa.Column("fingerprint_key", sa.String(64), nullable=False),
        sa.Column("incident_id", sa.Integer, sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("analyst_user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("verdict", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_key", "fingerprint_key"], ["fingerprints.tenant_key", "fingerprints.fingerprint_key"],
            name="fingerprint_verdicts_fingerprint_fkey",
        ),
        sa.CheckConstraint(
            "verdict IN ('acknowledged', 'escalated', 'false_positive')",
            name="fingerprint_verdicts_verdict_check",
        ),
    )
    op.create_index(
        "ix_fingerprint_verdicts_lookup", "fingerprint_verdicts",
        ["tenant_key", "fingerprint_key", "verdict"],
    )

    # Optional per-agent role tag (Step 3's target_class input) - changing
    # it changes which fingerprint a future incident on that agent
    # computes to; every change is audited (via the existing audit_log,
    # not a new table) by the route that updates this.
    op.create_table(
        "agent_role_tags",
        sa.Column("tenant_key", sa.String(64), nullable=False),
        sa.Column("agent_id", sa.String(255), nullable=False),
        sa.Column("role_tag", sa.String(100), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("tenant_key", "agent_id"),
    )

    bind = op.get_bind()
    for table in NEW_TABLES:
        bind.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {APP_ROLE}"))
    for table in ("incidents", "incident_alerts", "fingerprint_verdicts", "agent_role_tags"):
        # Only the 4 with a SERIAL/Integer primary key actually have a
        # sequence - fingerprints' PK is the (tenant_key, fingerprint_key)
        # composite, no sequence involved.
        if table != "agent_role_tags":
            bind.execute(text(f"GRANT USAGE, SELECT ON {table}_id_seq TO {APP_ROLE}"))


def downgrade() -> None:
    bind = op.get_bind()
    for table in NEW_TABLES:
        bind.execute(text(f"REVOKE ALL ON {table} FROM {APP_ROLE}"))
    op.drop_table("agent_role_tags")
    op.drop_table("fingerprint_verdicts")
    op.drop_table("fingerprints")
    op.drop_table("incident_alerts")
    op.drop_table("incidents")
