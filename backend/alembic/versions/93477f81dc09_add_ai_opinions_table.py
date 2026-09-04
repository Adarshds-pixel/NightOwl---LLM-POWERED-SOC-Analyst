"""add ai_opinions table

Revision ID: 93477f81dc09
Revises: 34c6df399e1a
Create Date: 2026-09-04 14:32:50.881118

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '93477f81dc09'
down_revision: Union[str, Sequence[str], None] = '34c6df399e1a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Hand-trimmed from the autogenerate output: it also proposed dropping
    `ix_alerts_event_id` and `ix_events_timestamp` again -- the same
    pre-existing, unrelated model/schema drift noted in
    34c6df399e1a_add_channel_to_events.py -- left alone here too.
    """
    op.create_table('ai_opinions',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('filename', sa.String(length=500), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('assessment_label', sa.String(length=50), nullable=True),
    sa.Column('summary', sa.String(), nullable=True),
    sa.Column('sample_event_ids', sa.JSON(), nullable=False),
    sa.Column('error', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('ai_opinions')
