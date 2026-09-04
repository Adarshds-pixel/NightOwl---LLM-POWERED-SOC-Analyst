"""`events` — raw normalized events (Vol1 §3.6).

v1 schema, expected to change once Day 5's normalizer defines the real
common event schema — this is the persistence shape for it, not the other
way around.
"""

from datetime import datetime

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    host: Mapped[str] = mapped_column(String(255))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_id: Mapped[int]
    # Raw `Event.System.Channel` (e.g. "Microsoft-Windows-Sysmon/Operational",
    # "Security"). A queryable column, not just part of raw_json, because
    # `event_id` alone is not unique across channels/providers -- any query
    # that needs to know "does this event have rule coverage" (see
    # event_service.list_events(covered=...)) has to filter on channel too,
    # not event_id alone. See detection/engine.py's covered_event_ids().
    channel: Mapped[str | None] = mapped_column(String(255))
    process: Mapped[str | None] = mapped_column(String(500))
    command_line: Mapped[str | None] = mapped_column(String)
    user: Mapped[str | None] = mapped_column(String(255))
    raw_json: Mapped[dict] = mapped_column(JSON)
