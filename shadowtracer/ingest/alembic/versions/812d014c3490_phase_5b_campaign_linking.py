"""phase 5b campaign linking

Revision ID: 812d014c3490
Revises: fa917f23b586
Create Date: 2026-10-07 22:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = '812d014c3490'
down_revision: Union[str, Sequence[str], None] = 'fa917f23b586'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    # Phase 5B Step 5: a campaign links incidents with the SAME
    # fingerprint AND the SAME actor (source IP first, then user - see
    # shadowtracer_correlate/campaigns.py) within a sliding 24h window.
    # Multiple campaign rows CAN exist for the same
    # (tenant_key, fingerprint_key, actor_type, actor_value) over time -
    # a gap past the window starts a brand new one rather than reusing
    # the old, so no uniqueness constraint on that tuple alone.
    op.create_table(
        "campaigns",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_key", sa.String(64), nullable=False),
        sa.Column("fingerprint_key", sa.String(64), nullable=False),
        sa.Column("actor_type", sa.String(20), nullable=False),
        sa.Column("actor_value", sa.String(255), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("incident_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("actor_type IN ('source_ip', 'user')", name="campaigns_actor_type_check"),
    )
    op.create_index(
        "ix_campaigns_lookup", "campaigns",
        ["tenant_key", "fingerprint_key", "actor_type", "actor_value", "last_seen"],
    )

    op.create_table(
        "campaign_incidents",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("campaign_id", sa.Integer, sa.ForeignKey("campaigns.id"), nullable=False),
        sa.Column("incident_id", sa.Integer, sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("tenant_key", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("campaign_id", "incident_id", name="campaign_incidents_identity_unique"),
    )

    bind = op.get_bind()
    for table in ("campaigns", "campaign_incidents"):
        bind.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {APP_ROLE}"))
        bind.execute(text(f"GRANT USAGE, SELECT ON {table}_id_seq TO {APP_ROLE}"))


def downgrade() -> None:
    op.drop_table("campaign_incidents")
    op.drop_table("campaigns")
