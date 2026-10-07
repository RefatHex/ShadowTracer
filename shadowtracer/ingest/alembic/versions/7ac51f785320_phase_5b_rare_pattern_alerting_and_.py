"""phase 5b rare pattern alerting and tenant alert settings

Revision ID: 7ac51f785320
Revises: 4d74a5d1c260
Create Date: 2026-10-07 20:12:50.971484

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = '7ac51f785320'
down_revision: Union[str, Sequence[str], None] = '4d74a5d1c260'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# shadowtracer_app is the restricted role the console backend and
# correlator actually connect as (see cfe022c4de55's identical pattern) -
# a new table with no grant for it is invisible to both, a real bug this
# migration's own test run against a real database caught (permission
# denied for table tenant_alert_settings).
APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    # Phase 5B Step 3: per-tenant configuration for the rare-pattern
    # warm-up guard. No row required for a tenant to use the defaults -
    # callers fall back to (7, 30) in Python when none exists. 30 is a
    # starting guess (see docs/specs/PHASE5B.md's addendum), not a
    # measured value - configurable per tenant specifically so it can be
    # corrected per-tenant without a code change once real volume is known.
    op.create_table(
        "tenant_alert_settings",
        sa.Column("tenant_key", sa.String(64), primary_key=True),
        sa.Column("rare_alert_warmup_days", sa.Integer, nullable=False, server_default="7"),
        sa.Column("rare_alert_warmup_min_incidents", sa.Integer, nullable=False, server_default="30"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # A rare-pattern alert is a FLAG on the incident, never a replacement
    # for it - the incident row and every column on it still exist
    # exactly as before regardless of this flag's value. rare_pattern_reason
    # is computed once at flag time and stored (not regenerated on read),
    # so the stated reason stays faithful to the logic that actually ran
    # even if that logic changes later.
    op.add_column("incidents", sa.Column("rare_pattern_flag", sa.Boolean, nullable=False, server_default="false"))
    op.add_column("incidents", sa.Column("rare_pattern_occurrence_count", sa.Integer, nullable=True))
    op.add_column("incidents", sa.Column("rare_pattern_reason", sa.Text, nullable=True))

    # incidents' existing grant (from cfe022c4de55) already covers these
    # new columns - only the new table needs one. No sequence grant: its
    # PK is tenant_key itself, no SERIAL/Integer identity column involved
    # (same as fingerprints').
    bind = op.get_bind()
    bind.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_alert_settings TO {APP_ROLE}"))


def downgrade() -> None:
    op.drop_column("incidents", "rare_pattern_reason")
    op.drop_column("incidents", "rare_pattern_occurrence_count")
    op.drop_column("incidents", "rare_pattern_flag")
    op.drop_table("tenant_alert_settings")
