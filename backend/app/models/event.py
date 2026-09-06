"""`events` — raw normalized events (Vol1 §3.6).

v1 schema, expected to change once Day 5's normalizer defines the real
common event schema — this is the persistence shape for it, not the other
way around.
"""

from datetime import datetime

from sqlalchemy import JSON, DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    host: Mapped[str] = mapped_column(String(255))
    # Indexed: the default sort/range-filter column for GET /events (see
    # migration 707e52de18cf, which created `ix_events_timestamp` directly
    # via op.create_index -- this `index=True` was missing from the model
    # itself, so a schema built via Base.metadata.create_all() (every
    # in-memory SQLite test DB) silently lacked the index even though real
    # Postgres has had it since that migration. Declaring it here keeps the
    # model and the real schema in agreement.
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event_id: Mapped[int]
    # Raw `Event.System.Channel` (e.g. "Microsoft-Windows-Sysmon/Operational",
    # "Security"). A queryable column, not just part of raw_json, because
    # `event_id` alone is not unique across channels/providers -- any query
    # that needs to know "does this event have rule coverage" (see
    # event_service.list_events(covered=...)) has to filter on channel too,
    # not event_id alone. See detection/engine.py's covered_event_ids().
    channel: Mapped[str | None] = mapped_column(String(255))
    # `Event.System.EventRecordID` -- a real identity Windows itself assigns
    # to every record, monotonically increasing per (host, channel) log.
    # Nullable because a genuinely malformed/legacy record can lack it, but
    # every real Windows event carries one. (host, channel, event_record_id)
    # is what event_service.find_existing_event_keys() dedups ingest on, so
    # uploading the same EVTX file (or a re-export overlapping an earlier
    # one) twice does not double every event/alert/incident-derived KPI.
    event_record_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    process: Mapped[str | None] = mapped_column(String(500))
    # `Image`/Security-aliased `NewProcessName`'s own parent, i.e. Sysmon's
    # `ParentImage` (event id 1) or the Security-aliased `ParentProcessName`
    # (4688) -- promoted onto its own column (pending.md "ParentImage
    # promotion") so it's searchable via GET /events?q= and visible in the
    # Logs UI table without opening the raw event. Only ever populated for
    # process-creation events (see normalizer.py's _normalize_process_creation);
    # None for every other event type, same as `process`/`command_line`.
    parent_process: Mapped[str | None] = mapped_column(String(500))
    command_line: Mapped[str | None] = mapped_column(String)
    user: Mapped[str | None] = mapped_column(String(255))
    raw_json: Mapped[dict] = mapped_column(JSON)

    __table_args__ = (Index("ix_events_dedup_key", "host", "channel", "event_record_id"),)
