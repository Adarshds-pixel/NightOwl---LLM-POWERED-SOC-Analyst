"""add events timestamp index and alerts event_id index

Revision ID: 707e52de18cf
Revises: eb2982ae8841
Create Date: 2026-08-25 18:43:21.124444

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '707e52de18cf'
down_revision: Union[str, Sequence[str], None] = 'eb2982ae8841'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Supports the new GET /events raw-timeline endpoint: events.timestamp is
    the default sort/range-filter column, and alerts.event_id backs the
    alert-only/normal-only filter's EXISTS subquery -- Postgres does not
    auto-index a foreign-key column, only the referenced primary-key side.
    """
    op.create_index('ix_events_timestamp', 'events', ['timestamp'])
    op.create_index('ix_alerts_event_id', 'alerts', ['event_id'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_alerts_event_id', table_name='alerts')
    op.drop_index('ix_events_timestamp', table_name='events')
