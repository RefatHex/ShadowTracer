"""phase 6.2: ioc_sightings.source_info (MISP event info, feed entry description)

Revision ID: a3d5f0c2b8e1
Revises: 7c1e9b2f4a60
Create Date: 2026-11-06

A MISP event's id goes in source_ref, its link in reference_url, its tags in labels
and its TLP in tlp; its human-readable info line had nowhere to go.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'a3d5f0c2b8e1'
down_revision: Union[str, Sequence[str], None] = '7c1e9b2f4a60'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.get_bind().execute(text("ALTER TABLE ioc_sightings ADD COLUMN source_info text"))


def downgrade() -> None:
    op.get_bind().execute(text("ALTER TABLE ioc_sightings DROP COLUMN source_info"))
