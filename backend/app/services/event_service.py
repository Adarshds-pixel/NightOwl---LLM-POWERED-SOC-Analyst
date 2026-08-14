"""Persists NormalizedEvent schemas as Event rows (Vol1 §3.4 layering:
routes -> services -> models/db; this is the only place that talks to the
DB for events).
"""

import logging

from sqlalchemy.orm import Session

from app.models.event import Event
from app.schemas.event import NormalizedEvent

logger = logging.getLogger(__name__)


def create_event(db: Session, normalized: NormalizedEvent) -> Event:
    """Builds and stages one Event row (add, no commit -- caller controls
    the transaction boundary; Day 6's ingest endpoint commits once per
    upload). raw_json keeps both the original raw record and the
    normalized view, so fields this module doesn't map onto flat columns
    (e.g. ParentImage, Hashes) aren't lost.
    """
    event = Event(
        host=normalized.host,
        timestamp=normalized.timestamp,
        event_id=normalized.event_id,
        process=normalized.process,
        command_line=normalized.command_line,
        user=normalized.user,
        raw_json={"raw": normalized.raw, "normalized": normalized.model_dump(mode="json")},
    )
    db.add(event)
    return event


def save_events(db: Session, events: list[NormalizedEvent]) -> list[Event]:
    """Persists a batch of normalized events in a single commit."""
    if not events:
        return []
    rows = [create_event(db, event) for event in events]
    db.commit()
    logger.info("ingested %d events", len(rows))
    return rows
