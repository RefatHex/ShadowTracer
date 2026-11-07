"""phase 7.1: incident anomaly score from the HalfSpaceTrees stream scorer

Revision ID: b2d4f6a8c0e1
Revises: d8a2e6f1c3b7
Create Date: 2026-11-07

The enrichment worker sets these at incident close: the incident's anomaly score is the MAX of
its alerts' live HST scores (ClickHouse ml_scores), with that alert's reasons. Separate from the
7.0 ml_score (the supervised/dummy incident model); both are advisory and never trigger actions.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'b2d4f6a8c0e1'
down_revision: Union[str, Sequence[str], None] = 'd8a2e6f1c3b7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("""
        ALTER TABLE incidents
          ADD COLUMN ml_anomaly_score   real,
          ADD COLUMN ml_anomaly_reasons jsonb,
          ADD COLUMN ml_anomaly_model   text
    """))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("ALTER TABLE incidents DROP COLUMN ml_anomaly_score, "
                      "DROP COLUMN ml_anomaly_reasons, DROP COLUMN ml_anomaly_model"))
