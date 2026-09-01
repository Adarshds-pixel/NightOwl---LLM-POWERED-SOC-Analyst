"""`incidents` — grouped alerts (Vol1 §3.6). Populated starting Day 9.

`mitre_technique_ids` uses JSON (not Postgres ARRAY) so the same model
works against both Postgres (prod/dev) and SQLite (offline tests) without
a dialect-specific type.
"""

from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String
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
