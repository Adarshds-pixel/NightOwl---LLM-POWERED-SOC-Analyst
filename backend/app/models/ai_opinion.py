"""`ai_opinions` -- an LLM's advisory read on an ingest whose events had no
loaded-rule coverage (Vol1 style: separate table, not `Alert`/`Incident`).

Deliberately its own table rather than a special kind of Alert: an opinion
is not a detection. It never carries a numeric severity score (only a
qualitative `assessment_label`), is never joined into incident evidence,
and its presence/absence has no effect on `alerts_created`/`incident_ids`
anywhere in the ingest response -- see services/ai_opinion_service.py.
"""

from datetime import datetime

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AiOpinion(Base):
    __tablename__ = "ai_opinions"

    id: Mapped[int] = mapped_column(primary_key=True)
    filename: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # "pending" | "ready" | "failed" -- set to "pending" at insert time
    # (before the LLM call), flipped by the background task once it
    # resolves. Never silently stuck: a failed LLM call still writes
    # status="failed" + error, so a poller always reaches a terminal state.
    status: Mapped[str] = mapped_column(String(20))
    # "worth_reviewing" | "nothing_unusual" | "uncertain" -- extracted from
    # the model's required response heading (see rag/prompts.py). A label,
    # not a score: nothing here should ever be styled or sorted like a real
    # Alert's severity.
    assessment_label: Mapped[str | None] = mapped_column(String(50))
    summary: Mapped[str | None] = mapped_column(String)
    # Event.id values the opinion was actually grounded in -- lets a caller
    # trace "why did it say this" back to real ingested rows.
    sample_event_ids: Mapped[list[int]] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(String)
