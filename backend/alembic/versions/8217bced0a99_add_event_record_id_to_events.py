"""add event_record_id to events

Revision ID: 8217bced0a99
Revises: 93477f81dc09
Create Date: 2026-09-04 22:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8217bced0a99'
down_revision: Union[str, Sequence[str], None] = '93477f81dc09'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Nullable, backfill-free: existing rows predate EventRecordID capture
    and simply never participate in duplicate detection (see
    event_service.find_existing_event_keys -- an Event with a NULL
    event_record_id is never matched as a duplicate of anything).
    """
    op.add_column('events', sa.Column('event_record_id', sa.Integer(), nullable=True))
    op.create_index('ix_events_dedup_key', 'events', ['host', 'channel', 'event_record_id'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_events_dedup_key', table_name='events')
    op.drop_column('events', 'event_record_id')
