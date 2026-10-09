"""phase 5c step 0 tenant integrity fks

Revision ID: 84445ac086c4
Revises: 812d014c3490
Create Date: 2026-10-08 12:35:40.243349

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '84445ac086c4'
down_revision: Union[str, Sequence[str], None] = '812d014c3490'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Phase 5C Step 0: every tenant-scoped table carries tenant_key as a plain
# string, with no FK into tenants - a forged, stale, or already-deleted
# tenant_key could silently create orphaned rows with no backing tenant
# (confirmed for real: a VERIFY script's replay section had been doing
# exactly this for days before this was caught - see
# PHASE3_DATA_PLATFORM.md's Phase 5C Step 0 entry). tenants.tenant_key is
# UNIQUE (not the primary key, which is the integer id - users.tenant_id
# already FKs to that), so a FK into it needs an explicit column list
# rather than the bare tenants.id most other FKs here use.
TENANT_KEY_TABLES = [
    "incidents", "incident_alerts", "fingerprints", "fingerprint_verdicts",
    "agent_role_tags", "tenant_alert_settings", "sequence_progress",
    "campaigns", "campaign_incidents",
]


def upgrade() -> None:
    for table in TENANT_KEY_TABLES:
        op.create_foreign_key(
            f"{table}_tenant_key_fkey", table, "tenants",
            ["tenant_key"], ["tenant_key"],
        )


def downgrade() -> None:
    for table in TENANT_KEY_TABLES:
        op.drop_constraint(f"{table}_tenant_key_fkey", table, type_="foreignkey")
