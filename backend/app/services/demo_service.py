"""Clears the operational data a demo run creates, so a replay can start
clean without dropping the schema.

Needed because nothing in the ingest pipeline deduplicates (see
services/ingest_service.py) and because incident grouping is anchored on
Incident.created_at (services/incident_service.py): a row left over from an
earlier demo run can silently absorb the next run's alerts if it falls
within that run's rebased +/-1h window, which would make a freshly-started
replay look like it detected nothing. A full reset removes that risk
entirely rather than trying to guess which rows are "demo" rows -- no
column distinguishes a replayed row from an uploaded one, and adding one
just to support a partial reset is exactly the kind of scope creep this
project avoids for a feature this narrow.
"""

from sqlalchemy import delete, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.audit_log import AuditLog
from app.models.chat_message import ChatMessage
from app.models.event import Event
from app.models.incident import Incident

# Delete order matters: children before the parents they reference.
# alerts.event_id -> events.id, alerts.incident_id -> incidents.id,
# chat_messages.incident_id -> incidents.id. audit_log has no FK (it stores
# entity_type/entity_id as plain values), so its position is not
# constrained, but it reads clearer grouped with the other per-incident
# history.
_RESET_ORDER = (
    ("chat_messages", ChatMessage),
    ("audit_log", AuditLog),
    ("alerts", Alert),
    ("incidents", Incident),
    ("events", Event),
)

# Identity sequences to restart after a reset, so a fresh demo opens at
# incident #1 / event #1 rather than continuing from wherever the last run
# left off -- purely cosmetic (nothing depends on low ids), but "INC-0001"
# reads better on stage than "INC-0847". Postgres-only: SQLite (used by the
# test suite) has no sequence to restart and reuses low rowids on its own.
_SEQUENCES = ("events_id_seq", "alerts_id_seq", "incidents_id_seq", "chat_messages_id_seq", "audit_log_id_seq")


def reset_demo_data(db: Session) -> dict[str, int]:
    """Deletes every row from the five operational tables, in FK-safe order,
    in one transaction. Returns {table_name: rows_deleted}. Schema,
    migrations and the detection rule files are untouched -- this is a data
    reset, not a teardown.
    """
    deleted: dict[str, int] = {}
    for table_name, model in _RESET_ORDER:
        result = db.execute(delete(model))
        deleted[table_name] = result.rowcount or 0

    _restart_sequences_if_postgres(db)

    db.commit()
    return deleted


def _restart_sequences_if_postgres(db: Session) -> None:
    engine: Engine = db.get_bind()
    if engine.dialect.name != "postgresql":
        return
    for sequence in _SEQUENCES:
        db.execute(text(f"ALTER SEQUENCE {sequence} RESTART WITH 1"))
