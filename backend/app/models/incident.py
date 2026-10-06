"""`incidents` — grouped alerts (Vol1 §3.6). Populated starting Day 9.

`mitre_technique_ids` uses JSON (not Postgres ARRAY) so the same model
works against both Postgres (prod/dev) and SQLite (offline tests) without
a dialect-specific type.
"""

from datetime import datetime

from sqlalchemy import JSON, DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(50), default="open")
    severity: Mapped[str] = mapped_column(String(50))
    # Same 1-5 rank as Alert.severity_score, bumped to the max of every
    # merged alert's score as new alerts join this incident (mirrors how
    # `severity` itself is bumped via severity_service.higher_severity).
    severity_score: Mapped[int] = mapped_column(Integer, default=3, server_default="3")
    mitre_technique_ids: Mapped[list[str]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Alerts are grouped into one incident by same host + time window
    # (Day 9) -- stored directly here rather than derived by joining
    # through alerts->events on every grouping lookup.
    host: Mapped[str] = mapped_column(String(255))
    # Timestamp of the newest alert merged in. The grouping window slides
    # with it (incident_service.find_or_create_incident), so one long attack
    # stays one incident instead of splitting 60 minutes after its first
    # alert. Nullable only for rows created before the column existed;
    # readers fall back to created_at.
    last_activity_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # incident_service.find_or_create_incident() runs one SELECT per rule/
    # sequence match during ingest, filtered on exactly these 3 columns
    # (host, status, created_at within the 1h grouping window) -- none were
    # indexed before this (verified: absent from every migration touching
    # `incidents`, not just this model). At this project's current fixture
    # scale that N-queries-per-ingest pattern is measured as acceptable on
    # its own (see ingest_service.py's comment above the per-match loop),
    # but each of those N queries was a full sequential scan; this index is
    # the actual fix for that cost, not a restructure of the query count.
    __table_args__ = (Index("ix_incidents_host_status_created_at", "host", "status", "created_at"),)
