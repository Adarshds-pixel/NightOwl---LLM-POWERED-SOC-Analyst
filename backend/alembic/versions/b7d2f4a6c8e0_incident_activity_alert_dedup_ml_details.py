"""incident last_activity_at, alert occurrence counting + ML details, missing
indexes, host case normalisation

Revision ID: b7d2f4a6c8e0
Revises: a1c3e5f7b9d1
Create Date: 2026-10-06

* incidents.last_activity_at -- incident grouping now slides with the latest
  alert instead of staying anchored on the first one (an attack running from
  0 to 70 minutes used to split in two at the 60-minute mark).
* alerts.occurrence_count / last_matched_at -- repeated identical matches
  (same rule, host, process, command line within a short window) fold into
  one alert with a count instead of e.g. 83 rows from one capture.
* alerts.details -- structured per-alert evidence (used by the ML anomaly
  layer for its score, window and top contributing features).
* indexes on alerts.incident_id and chat_messages.incident_id -- the incident
  detail, evidence and chat queries filter on them and were scanning.
* events.host / incidents.host upper-cased -- the normalizer now upper-cases
  host names (Windows names are case-insensitive); rows stored before that
  change would otherwise never match the dedup key or open-incident lookup.
* the `rules` table is dropped -- it was created by the initial schema but
  never read or written; detection rules live as YAML files.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b7d2f4a6c8e0"
down_revision: Union[str, Sequence[str], None] = "a1c3e5f7b9d1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("incidents", sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=True))
    op.execute("UPDATE incidents SET last_activity_at = created_at WHERE last_activity_at IS NULL")

    op.add_column(
        "alerts", sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1")
    )
    op.add_column("alerts", sa.Column("last_matched_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("alerts", sa.Column("details", sa.JSON(), nullable=True))

    op.create_index("ix_alerts_incident_id", "alerts", ["incident_id"])
    op.create_index("ix_chat_messages_incident_id", "chat_messages", ["incident_id"])

    op.execute("UPDATE events SET host = UPPER(TRIM(host)) WHERE host <> UPPER(TRIM(host))")
    op.execute("UPDATE incidents SET host = UPPER(TRIM(host)) WHERE host <> UPPER(TRIM(host))")

    op.drop_table("rules")


def downgrade() -> None:
    op.create_table(
        "rules",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("mitre_technique_id", sa.String(length=20), nullable=True),
        sa.Column("yaml_path", sa.String(length=500), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.drop_index("ix_chat_messages_incident_id", table_name="chat_messages")
    op.drop_index("ix_alerts_incident_id", table_name="alerts")
    op.drop_column("alerts", "details")
    op.drop_column("alerts", "last_matched_at")
    op.drop_column("alerts", "occurrence_count")
    op.drop_column("incidents", "last_activity_at")
