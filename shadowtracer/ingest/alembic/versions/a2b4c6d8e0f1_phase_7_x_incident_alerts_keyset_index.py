"""phase 7.x: keyset index for incident-alert pagination

Revision ID: a2b4c6d8e0f1
Revises: f1a7c3e5b9d2
Create Date: 2026-11-21

The incident detail/alerts endpoints page an incident's alerts by (alert_time, id). A very large
incident (>100k alerts - e.g. an SSH brute force) would otherwise sort every membership row per page;
this composite index makes each keyset page index-only so incident 394326 opens in well under 3 s.
CONCURRENTLY so it never locks the table while the pipeline is writing incident_alerts.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'a2b4c6d8e0f1'
down_revision: Union[str, Sequence[str], None] = 'f1a7c3e5b9d2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # CONCURRENTLY can't run inside a transaction - run it outside alembic's migration transaction.
    with op.get_context().autocommit_block():
        op.execute(text(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_incident_alerts_incident_time_id "
            "ON incident_alerts (incident_id, alert_time, id)"))


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute(text("DROP INDEX CONCURRENTLY IF EXISTS ix_incident_alerts_incident_time_id"))
