"""add limitations and attack_candidate_ids to ai_opinions

Revision ID: 01bdb3f3142e
Revises: f590a24f0691
Create Date: 2026-09-10 22:47:22.005378

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '01bdb3f3142e'
down_revision: Union[str, Sequence[str], None] = 'f590a24f0691'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Both nullable, no server_default -- unlike severity_score's backfill
    case, there's nothing to backfill: existing rows and any pending/failed
    opinion simply have NULL, same as assessment_label/summary/error
    already do. See models/ai_opinion.py for what each column holds.
    """
    op.add_column('ai_opinions', sa.Column('limitations', sa.String(), nullable=True))
    op.add_column('ai_opinions', sa.Column('attack_candidate_ids', sa.JSON(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('ai_opinions', 'attack_candidate_ids')
    op.drop_column('ai_opinions', 'limitations')
