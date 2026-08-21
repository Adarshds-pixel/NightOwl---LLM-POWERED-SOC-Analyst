"""`audit_log` -- who/when for incident status changes and explain/chat
calls (Day 13 production hardening).

`details` uses JSON (not Postgres JSONB) for the same dual-dialect reason as
`Incident.mitre_technique_ids` (app/models/incident.py): the same model
needs to work against both Postgres (prod/dev) and SQLite (offline tests).

`actor` has no real user identity to draw on yet -- there's no auth/user
model in this codebase (Pair 1's Day 13 API key auth is a single shared
secret, not per-user) -- so it defaults to a fixed "system" string until a
real identity concept exists.
"""

from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(50))
    entity_id: Mapped[int] = mapped_column(Integer)
    action: Mapped[str] = mapped_column(String(50))
    actor: Mapped[str] = mapped_column(String(255))
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
