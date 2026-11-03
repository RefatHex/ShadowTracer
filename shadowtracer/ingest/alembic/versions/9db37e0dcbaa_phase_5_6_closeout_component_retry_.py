"""phase 5.6 closeout: component retry state for health detail

Revision ID: 9db37e0dcbaa
Revises: 8638c1abc22b
Create Date: 2026-11-03 22:45:52.226443

Phase 5.6 closeout, item 3: a writer/correlator consumer paused in its
dead-letter retry-forever loop is invisible to console-backend's
/health endpoints today - they query Kafka directly (consumer group
offsets/lag), which can't distinguish "genuinely processing" from
"stuck retrying the same message" (both just look like normal lag).
Each writer/correlator process now upserts one row here per retry
attempt (writer.py/consumer.py's on_retry callbacks, see retry_state.py)
and deletes it the moment the retry succeeds - health.py reads it
directly, no Kafka admin API involved.

One row per component (not per message/attempt): a retry sequence is
"still stuck on the same thing" until it either succeeds (row deleted)
or the process restarts (row stays, correctly flagging a dead-lettered
message still unresolved across the restart - the next attempt's first
on_retry call just re-upserts the same stuck_since, see retry_state.py).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = '9db37e0dcbaa'
down_revision: Union[str, Sequence[str], None] = '8638c1abc22b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    op.create_table(
        "component_retry_state",
        sa.Column("component", sa.Text, primary_key=True),
        sa.Column("group_id", sa.Text, nullable=False),
        sa.Column("partitions_paused", sa.Text, nullable=False),
        sa.Column("stuck_since", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_error", sa.Text, nullable=False),
    )
    # writer.py/consumer.py connect as shadowtracer_app (the restricted
    # role - see 5f408777ad31's own docstring), not the table-owning
    # migration role - confirmed the hard way: without this grant,
    # mark_stuck's INSERT fails with "permission denied for table
    # component_retry_state" (caught and logged, never fatal, but the
    # whole feature silently does nothing).
    op.get_bind().execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON component_retry_state TO {APP_ROLE}"))


def downgrade() -> None:
    op.drop_table("component_retry_state")
