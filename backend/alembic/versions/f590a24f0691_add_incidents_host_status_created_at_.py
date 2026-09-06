"""add incidents host status created_at index

Revision ID: f590a24f0691
Revises: cedb212e01f4
Create Date: 2026-09-06 18:26:25.246023

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f590a24f0691'
down_revision: Union[str, Sequence[str], None] = 'cedb212e01f4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    incident_service.find_or_create_incident()'s hot-path SELECT (called
    once per rule/sequence match during ingest) filters on exactly host +
    status + created_at (within the 1h grouping window) -- none of the
    three were indexed before this, on any prior migration touching
    `incidents`, so every one of those repeated per-ingest queries was a
    full sequential scan.
    """
    op.create_index('ix_incidents_host_status_created_at', 'incidents', ['host', 'status', 'created_at'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_incidents_host_status_created_at', table_name='incidents')
