"""phase 4 followups tenant key

Revision ID: 6d5b50d3e5b5
Revises: 5f408777ad31
Create Date: 2026-10-03 11:44:13.038282

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6d5b50d3e5b5'
down_revision: Union[str, Sequence[str], None] = '5f408777ad31'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # The tenant's permanent, immutable identity - stamped onto every
    # ClickHouse event by the shipper and embedded in every access token,
    # so neither needs a per-request Postgres lookup and neither is
    # affected by renaming the tenant's (display-only) name. No API or
    # CLI path ever updates this column once set.
    op.add_column("tenants", sa.Column("tenant_key", sa.String(64), nullable=True))
    # Backfill any pre-existing rows with a random key before enforcing
    # NOT NULL + unique - no pgcrypto dependency, just enough randomness
    # for a value nothing will ever need to guess.
    op.execute("UPDATE tenants SET tenant_key = md5(random()::text || clock_timestamp()::text) WHERE tenant_key IS NULL")
    op.alter_column("tenants", "tenant_key", nullable=False)
    op.create_unique_constraint("tenants_tenant_key_unique", "tenants", ["tenant_key"])


def downgrade() -> None:
    op.drop_constraint("tenants_tenant_key_unique", "tenants", type_="unique")
    op.drop_column("tenants", "tenant_key")
