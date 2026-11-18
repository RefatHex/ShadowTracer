"""phase 7.5: track similar-incident index state on incidents

Revision ID: f1a7c3e5b9d2
Revises: e9c3b7a1d2f4
Create Date: 2026-11-16

The ml-enricher embeds each closed incident's structured-text at close and upserts the vector to
Qdrant. These two columns record that it happened and under which text+model version, so a version
bump re-indexes and the backfill knows what is still un-indexed. Advisory; nothing acts on them.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'f1a7c3e5b9d2'
down_revision: Union[str, Sequence[str], None] = 'e9c3b7a1d2f4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("ALTER TABLE incidents ADD COLUMN ml_sim_indexed_at timestamptz"))
    conn.execute(text("ALTER TABLE incidents ADD COLUMN ml_sim_text_version text"))
    # the enricher queries un-indexed closed incidents by this predicate
    conn.execute(text("CREATE INDEX incidents_sim_unindexed ON incidents (closed_at) "
                      "WHERE state = 'closed' AND ml_sim_indexed_at IS NULL"))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("DROP INDEX IF EXISTS incidents_sim_unindexed"))
    conn.execute(text("ALTER TABLE incidents DROP COLUMN ml_sim_text_version"))
    conn.execute(text("ALTER TABLE incidents DROP COLUMN ml_sim_indexed_at"))
