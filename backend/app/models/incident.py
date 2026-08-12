"""`incidents` — grouped alerts (Vol1 §3.6). Populated starting Day 9.

`mitre_technique_ids` uses JSON (not Postgres ARRAY) so the same model
works against both Postgres (prod/dev) and SQLite (offline tests) without
a dialect-specific type.
"""

from datetime import datetime

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(50), default="open")
    severity: Mapped[str] = mapped_column(String(50))
    mitre_technique_ids: Mapped[list[str]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
