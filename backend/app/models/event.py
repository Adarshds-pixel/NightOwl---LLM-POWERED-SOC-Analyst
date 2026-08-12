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
    process: Mapped[str | None] = mapped_column(String(500))
    command_line: Mapped[str | None] = mapped_column(String)
    user: Mapped[str | None] = mapped_column(String(255))
    raw_json: Mapped[dict] = mapped_column(JSON)
