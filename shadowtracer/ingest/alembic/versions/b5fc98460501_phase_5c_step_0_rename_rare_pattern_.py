"""phase 5c step 0 rename rare pattern occurrence count

Revision ID: b5fc98460501
Revises: 84445ac086c4
Create Date: 2026-10-09 14:46:14.409873

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'b5fc98460501'
down_revision: Union[str, Sequence[str], None] = '84445ac086c4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Phase 5C Step 0: "rare_pattern_occurrence_count" was never actually a
# count of occurrences - evaluate_rare_pattern (shadowtracer_correlate/
# rarity.py) only ever flags on prior_count == 0 ("never seen before"),
# so the column's one real value is always 0. Renamed to what it means:
# how many times this exact fingerprint was seen for this tenant before
# this incident - "prior occurrences".


def upgrade() -> None:
    op.alter_column("incidents", "rare_pattern_occurrence_count", new_column_name="prior_occurrences")


def downgrade() -> None:
    op.alter_column("incidents", "prior_occurrences", new_column_name="rare_pattern_occurrence_count")
