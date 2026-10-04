"""phase 5a add rule_groups and agent os_family for fingerprinting

Revision ID: 4d74a5d1c260
Revises: cfe022c4de55
Create Date: 2026-10-04 09:54:07.282778

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4d74a5d1c260'
down_revision: Union[str, Sequence[str], None] = 'cfe022c4de55'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


from sqlalchemy.dialects.postgresql import ARRAY


def upgrade() -> None:
    # Step 3's fingerprint hash needs "sorted rule groups" - not captured
    # on incidents until now (only rule_ids and mitre_ids were).
    op.add_column("incidents", sa.Column("rule_groups", ARRAY(sa.String), nullable=False, server_default="{}"))

    # Step 3's target class is "OS family plus optional role tag" - real
    # Wazuh 4.14.8 alerts carry no OS info at all (confirmed against
    # fixtures/real_alerts_4.14.8.jsonl), so, like role_tag, this has to
    # be admin-set metadata rather than derived from the alert stream.
    op.add_column("agent_role_tags", sa.Column("os_family", sa.String(50), nullable=True))


def downgrade() -> None:
    op.drop_column("agent_role_tags", "os_family")
    op.drop_column("incidents", "rule_groups")
