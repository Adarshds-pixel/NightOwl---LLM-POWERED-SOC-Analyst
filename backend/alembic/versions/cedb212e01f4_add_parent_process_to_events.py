"""add parent_process to events

Revision ID: cedb212e01f4
Revises: 8217bced0a99
Create Date: 2026-09-05 19:26:06.467355

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'cedb212e01f4'
down_revision: Union[str, Sequence[str], None] = '8217bced0a99'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Unlike event_record_id's migration (nullable, backfill-free -- old
    rows genuinely never captured that field), ParentImage is already
    sitting untouched in every existing row's raw_json (see
    event_service.create_event's own comment on why raw_json keeps fields
    normalization doesn't flatten). "Promoting" it should mean every
    already-ingested process-creation event gets it too, not just events
    ingested from here on -- so this backfills in the same migration,
    pulling it out with Postgres's own JSON path operators rather than a
    per-row Python loop (thousands of ingested-event rows in a real
    deployment, and every one of them already has this exact value sitting
    in a JSON column -- one UPDATE does the same work as row-by-row
    without a client round trip per row). NULL-safe: rows with no
    ParentImage (every non-process-creation event type) or malformed/
    pre-this-shape raw_json simply keep a NULL parent_process, same as any
    other genuinely-absent field on this table.
    """
    op.add_column("events", sa.Column("parent_process", sa.String(length=500), nullable=True))
    op.execute(
        """
        UPDATE events
        SET parent_process = raw_json #>> '{normalized,event_data,ParentImage}'
        WHERE raw_json #>> '{normalized,event_data,ParentImage}' IS NOT NULL
        """
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("events", "parent_process")
