"""add channel to events

Revision ID: 34c6df399e1a
Revises: 9c4e1f2a7b3d
Create Date: 2026-09-04 11:37:33.780197

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '34c6df399e1a'
down_revision: Union[str, Sequence[str], None] = '9c4e1f2a7b3d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Hand-trimmed from the autogenerate output: it also proposed dropping
    `ix_alerts_event_id` and `ix_events_timestamp`, a pre-existing drift
    between the model files and the live schema unrelated to this change
    -- left alone rather than silently dropped by an unrelated migration.
    """
    op.add_column('events', sa.Column('channel', sa.String(length=255), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('events', 'channel')
