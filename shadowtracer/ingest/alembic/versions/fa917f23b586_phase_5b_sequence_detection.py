"""phase 5b sequence detection

Revision ID: fa917f23b586
Revises: 7ac51f785320
Create Date: 2026-10-07 21:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision: str = 'fa917f23b586'
down_revision: Union[str, Sequence[str], None] = '7ac51f785320'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "shadowtracer_app"


def upgrade() -> None:
    # Phase 5B Step 4: the ONLY mutable sequence-detection state - "how
    # far along is this (tenant, sequence, agent, attacker-key) right
    # now" - never held in a worker's memory (a restart mid-sequence must
    # not lose progress). One row per (tenant_key, sequence_id, agent_id,
    # key_type, key_value) - reset to current_step=0 whenever a sequence
    # completes (the firing itself is recorded in ClickHouse's
    # sequence_firings, history, not here) or whenever its window expires
    # and a fresh step-0 match restarts it.
    op.create_table(
        "sequence_progress",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_key", sa.String(64), nullable=False),
        sa.Column("sequence_id", sa.String(100), nullable=False),
        sa.Column("agent_id", sa.String(255), nullable=False),
        sa.Column("key_type", sa.String(20), nullable=False),
        sa.Column("key_value", sa.String(255), nullable=False),
        sa.Column("current_step", sa.Integer, nullable=False, server_default="0"),
        sa.Column("first_step_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_step_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("step_matches", JSONB, nullable=False, server_default="[]"),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint(
            "tenant_key", "sequence_id", "agent_id", "key_type", "key_value",
            name="sequence_progress_identity_unique",
        ),
        sa.CheckConstraint("key_type IN ('source_ip', 'user')", name="sequence_progress_key_type_check"),
    )

    bind = op.get_bind()
    bind.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON sequence_progress TO {APP_ROLE}"))
    bind.execute(text(f"GRANT USAGE, SELECT ON sequence_progress_id_seq TO {APP_ROLE}"))


def downgrade() -> None:
    op.drop_table("sequence_progress")
