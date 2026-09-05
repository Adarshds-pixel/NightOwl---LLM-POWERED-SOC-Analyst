"""LLM second-opinion generation, triggered either by an ingest whose events
had zero rule coverage or by a narrow, verified advisory pattern
(services/advisory_patterns.py) that a deterministic rule can't safely
absorb -- see routes_ingest.py for exactly which conditions create one.
Advisory only, never a detector (see models/ai_opinion.py's module
docstring for the "not a detection" boundary this module exists to
preserve, and rag/prompts.py's UNCOVERED_OPINION_SYSTEM_PROMPT for how
that boundary is enforced at the model level too, not just in the API/UI).

`fill_in_opinion` is meant to run as a FastAPI BackgroundTask, scheduled by
routes_ingest.py *after* the /ingest response has already been built --
so a slow or failing LLM call can never add latency to, or fail, the
ingest request itself. It opens its own DB session (SessionLocal) rather
than reusing the request's, since that session may already be closed by
the time a background task actually runs.
"""

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models.ai_opinion import AiOpinion
from app.models.event import Event
from app.rag.llm_client import LLMProviderError, generate
from app.rag.prompts import build_uncovered_opinion_prompt, extract_assessment_label
from app.rag.retriever import retrieve

logger = logging.getLogger(__name__)

DEFAULT_K = 3
# Bounds both the LLM prompt size and how much of a large uncovered file
# gets sent to a third-party API -- one sample per distinct (channel,
# event_id) group is plenty to give an informed opinion without shipping
# the whole ingest.
MAX_SAMPLE_EVENTS = 5


def create_pending_opinion(db: Session, filename: str, sample_event_ids: list[int]) -> AiOpinion:
    """Synchronous insert (fast -- just a row write, not the LLM call) so
    `POST /ingest` can return `ai_opinion_id` immediately; the slow part
    happens in fill_in_opinion(), scheduled as a background task."""
    opinion = AiOpinion(
        filename=filename,
        created_at=datetime.now(timezone.utc),
        status="pending",
        sample_event_ids=sample_event_ids[:MAX_SAMPLE_EVENTS],
    )
    db.add(opinion)
    db.commit()
    db.refresh(opinion)
    return opinion


def _event_summary(event: Event) -> dict:
    """Only fields already public via GET /events -- never raw_json. What
    the LLM sees here is exactly what an analyst could already see in the
    UI, nothing more."""
    return {
        "channel": event.channel,
        "event_id": event.event_id,
        "host": event.host,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "process": event.process,
        "command_line": event.command_line,
        "user": event.user,
    }


def _build_retrieval_query(filename: str, samples: list[dict]) -> str:
    parts: list[object] = [filename]
    for sample in samples:
        parts.extend([sample.get("channel"), sample.get("process"), sample.get("command_line")])
    query = " ".join(str(p) for p in parts if p)
    return query or "uncovered windows telemetry"


def _mark_failed(db: Session, opinion_id: int, error: str) -> None:
    db.rollback()  # clear any partial/aborted transaction state before writing the failure
    opinion = db.get(AiOpinion, opinion_id)
    if opinion is None:
        logger.warning("ai_opinion %d not found while marking failed", opinion_id)
        return
    opinion.status = "failed"
    opinion.error = error
    db.commit()


def fill_in_opinion(opinion_id: int, filename: str, sample_event_ids: list[int]) -> None:
    db = SessionLocal()
    try:
        events = db.query(Event).filter(Event.id.in_(sample_event_ids)).all() if sample_event_ids else []
        samples = [_event_summary(e) for e in events[:MAX_SAMPLE_EVENTS]]

        query = _build_retrieval_query(filename, samples)
        chunks = retrieve(query, k=DEFAULT_K)

        reply = generate(build_uncovered_opinion_prompt(filename, samples, chunks))
        label = extract_assessment_label(reply)

        opinion = db.get(AiOpinion, opinion_id)
        if opinion is None:
            logger.warning("ai_opinion %d not found when filling in", opinion_id)
            return
        opinion.status = "ready"
        opinion.assessment_label = label
        opinion.summary = reply
        db.commit()
    except LLMProviderError as e:
        logger.warning("ai_opinion %d: LLM call failed: %s", opinion_id, e)
        _mark_failed(db, opinion_id, str(e))
    except Exception as e:  # noqa: BLE001 -- a background task must never raise into the void unlogged
        logger.exception("ai_opinion %d: unexpected failure", opinion_id)
        _mark_failed(db, opinion_id, str(e))
    finally:
        db.close()
