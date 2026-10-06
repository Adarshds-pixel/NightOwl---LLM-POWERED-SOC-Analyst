"""`alerts` — detection matches (Vol1 §3.6). Populated starting Day 8."""

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Indexed: Postgres does not auto-index a foreign-key column (only the
    # referenced primary-key side), and GET /events' alert-only/normal-only
    # filter runs an EXISTS subquery on this column (see migration
    # 707e52de18cf). `index=True` here keeps the model in agreement with
    # that migration -- without it, a schema built via
    # Base.metadata.create_all() (every in-memory SQLite test DB) silently
    # lacks the index real Postgres has had since that migration.
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(255))
    matched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    severity: Mapped[str] = mapped_column(String(50))
    # The 1-5 rank `severity` was derived from (severity_service.compute_severity_score)
    # -- kept alongside the label instead of discarded, so the UI can show a
    # score, not just the label. Defaults to 3 (medium's rank) so the many
    # existing tests that construct Alert() without this field still work.
    severity_score: Mapped[int] = mapped_column(Integer, default=3, server_default="3")
    # Nullable: grouping into an incident happens right after the alert is
    # created (Day 9), but the FK is optional at the schema level so an
    # alert is never blocked from being persisted by grouping failing.
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)
    # Identical repeat matches (same rule + host + process + command line
    # within ALERT_DEDUP_WINDOW, see ingest_service) fold into this one row:
    # how many times it fired, and when it last did.
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    last_matched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Structured evidence that is not a rule match on one event -- the ML
    # anomaly layer stores its score, window bounds and top contributing
    # features here (app/ml/). None for ordinary rule alerts.
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
