"""`alerts` — detection matches (Vol1 §3.6). Populated starting Day 8."""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"))
    rule_id: Mapped[str] = mapped_column(String(255))
    matched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    severity: Mapped[str] = mapped_column(String(50))
    # Nullable: grouping into an incident happens right after the alert is
    # created (Day 9), but the FK is optional at the schema level so an
    # alert is never blocked from being persisted by grouping failing.
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True)
