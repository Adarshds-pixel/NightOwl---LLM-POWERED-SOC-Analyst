"""`ai_opinions` -- an LLM's advisory read on an ingest, triggered either by
events with no loaded-rule coverage or by a narrow, verified advisory
pattern a deterministic rule can't safely absorb (see
services/advisory_patterns.py, routes_ingest.py) (Vol1 style: separate
table, not `Alert`/`Incident`).

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
    # The parsed "## Limitations" section of `summary` (see
    # rag/prompts.py's UNCOVERED_LIMITATIONS_HEADING) -- always populated
    # alongside a successful `summary`, independent of assessment_label, so
    # "worth reviewing" and "the sample is too thin to establish intent" can
    # both be recorded rather than forcing one or the other. Nullable for
    # the same reason summary is: pending/failed opinions, or a response
    # that didn't follow the required format (extract_uncovered_limitations
    # returns "" in that case, stored as None here rather than an empty
    # string, so a caller can tell "no limitations text" apart from
    # "opinion not ready yet").
    limitations: Mapped[str | None] = mapped_column(String, nullable=True)
    # Structured ATT&CK candidates, sourced ONLY from retrieved MITRE KB
    # chunk metadata (see ai_opinion_service._attack_candidate_ids) --
    # mirrors Incident.mitre_technique_ids' shape and purpose (a flat,
    # queryable id list) for the same reason. Deliberately never populated
    # from the LLM's own prose: a technique can appear here only if this
    # run's retrieve() call actually returned a chunk carrying that id, so
    # this list is structurally incapable of holding a hallucinated
    # technique. Empty list (not None) when no MITRE chunk was retrieved.
    attack_candidate_ids: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
