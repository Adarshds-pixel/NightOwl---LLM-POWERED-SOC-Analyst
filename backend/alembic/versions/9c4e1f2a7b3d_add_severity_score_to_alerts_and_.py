"""add severity_score to alerts and incidents

Revision ID: 9c4e1f2a7b3d
Revises: 707e52de18cf
Create Date: 2026-08-31 20:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9c4e1f2a7b3d'
down_revision: Union[str, Sequence[str], None] = '707e52de18cf'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    severity_service.compute_severity() has always computed a 1-5 numeric
    rank internally (base Sigma level + tactic weight) before collapsing it
    to a label -- this surfaces that rank as a real column instead of
    discarding it, so the UI can show e.g. "Critical - 5/5" rather than only
    ever the label. server_default backfills existing rows to 3 (medium's
    rank); new rows always get a real computed value from
    detection_service.create_alert / incident_service.find_or_create_incident.
    """
    op.add_column('alerts', sa.Column('severity_score', sa.Integer(), nullable=False, server_default='3'))
    op.add_column('incidents', sa.Column('severity_score', sa.Integer(), nullable=False, server_default='3'))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('incidents', 'severity_score')
    op.drop_column('alerts', 'severity_score')
