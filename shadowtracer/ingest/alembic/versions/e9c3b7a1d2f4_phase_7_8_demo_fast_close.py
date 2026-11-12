"""phase 7.8: per-tenant demo fast-close window

Revision ID: e9c3b7a1d2f4
Revises: d7f2a9c4b6e8
Create Date: 2026-11-13

A demo-only knob: when tenant_alert_settings.demo_fast_close_seconds is set, the incident closer
uses it as that tenant's session-gap instead of the global SESSION_GAP_SECONDS (default 600), so
incidents close within ~a minute during a live demo and the Live view shows them opening AND
closing. NULL = off (the global gap applies), which is the default for every tenant - this changes
no behaviour until someone explicitly sets it. Shown as a demo setting in the console.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = 'e9c3b7a1d2f4'
down_revision: Union[str, Sequence[str], None] = 'd7f2a9c4b6e8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.get_bind().execute(text(
        "ALTER TABLE tenant_alert_settings ADD COLUMN demo_fast_close_seconds integer "
        "CHECK (demo_fast_close_seconds IS NULL OR demo_fast_close_seconds BETWEEN 10 AND 3600)"
    ))


def downgrade() -> None:
    op.get_bind().execute(text("ALTER TABLE tenant_alert_settings DROP COLUMN demo_fast_close_seconds"))
