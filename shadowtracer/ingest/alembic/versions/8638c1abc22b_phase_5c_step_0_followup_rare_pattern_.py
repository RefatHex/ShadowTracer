"""phase 5c step 0 followup rare pattern prior occurrence threshold

Revision ID: 8638c1abc22b
Revises: b5fc98460501
Create Date: 2026-10-09 18:05:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8638c1abc22b'
down_revision: Union[str, Sequence[str], None] = 'b5fc98460501'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Phase 5C Step 0 follow-up: "rare" was hardcoded as "prior_count == 0" -
# per-tenant configurable now (default 0, unchanged behavior for every
# existing tenant), so a tenant can choose to flag "seen at most N times
# before" instead of strictly "never seen before", without a code change.


def upgrade() -> None:
    op.add_column(
        "tenant_alert_settings",
        sa.Column("rare_alert_prior_occurrence_threshold", sa.Integer, nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("tenant_alert_settings", "rare_alert_prior_occurrence_threshold")
