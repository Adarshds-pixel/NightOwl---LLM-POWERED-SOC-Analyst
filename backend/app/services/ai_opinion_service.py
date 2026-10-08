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
from app.ingestion.normalizer import canonical_channel
from app.models.ai_opinion import AiOpinion
from app.models.event import Event
from app.rag.llm_client import LLMProviderError, generate
from app.rag.prompts import build_uncovered_opinion_prompt, extract_assessment_label, extract_uncovered_limitations
from app.rag.retriever import retrieve
from app.rag.safety import annotate_unknown_technique_ids
from app.services.ingest_service import UncoveredEventGroup

logger = logging.getLogger(__name__)

# Sysmon event id -> human label, mirroring frontend/src/lib/constants.ts's
# SYSMON_EVENT_TYPE_LABELS exactly (same 5 entries, same wording) so an
# analyst reading the AI opinion and the Logs page's own event-type badges
# never sees two different names for the same event id. Gated to the
# Sysmon channel specifically -- confirmed live during this feature's own
# testing that the model, given only a bare `"event_id": 5`, guessed that
# number meant "process creation" (it's actually Process Terminated) and
# said so in its reasoning; raw Windows event ids are not unique across
# channels (Security event 5 means something unrelated), so labeling one
# without the channel check would just trade one mislabeling for another.
# Deliberately not extended to other channels here: this is a label
# lookup for ids this project's own rules already treat as meaningful
# categories (see detection/engine.py's CATEGORY_TO_EVENT_ID), not a new
# per-channel reference table built for this feature.
_SYSMON_EVENT_TYPE_LABELS: dict[int, str] = {
    1: "Process Creation",
    3: "Network Connection",
    5: "Process Terminated",
    11: "File Created",
    13: "Registry Event",
}

DEFAULT_K = 3
# Bounds both the LLM prompt size and how much of a large uncovered file
# gets sent to a third-party API -- ingest_service.py's round-robin
# selection (not this module) is what guarantees these are one-per-
# distinct-(channel,event_id)-group before any group gets a second; this
# cap only bounds the total payload/prompt size, same as before.
MAX_SAMPLE_EVENTS = 8

# A retrieved KB chunk's metadata["source_type"] value for a real MITRE
# ATT&CK technique document (see ai/tools/build_kb.py) -- the other value,
# "playbook", is real guidance text but not a technique the model should
# cite as a structured candidate. Only mitre_technique chunks populate
# attack_candidate_ids -- deliberately never the LLM's own free-form prose,
# so a candidate can't exist that isn't traceable to a real retrieved
# document (see prompts.py's UNCOVERED_OPINION_SYSTEM_PROMPT for the
# corresponding instruction not to invent technique IDs in prose either).
_MITRE_TECHNIQUE_SOURCE_TYPE = "mitre_technique"

# Retrieval score (1 / (1 + L2 distance)) a MITRE chunk must reach before its
# technique is offered as a structured candidate. Measured on the corpus:
# genuinely related techniques scored 0.52-0.58, unrelated nearest
# neighbours 0.42-0.47. Without a floor, the top-3 nearest chunks were
# returned as "candidates" even when the opinion found nothing unusual.
MIN_CANDIDATE_SCORE = 0.5

# Why each sampled event is in front of the model -- passed through as the
# sample's `why_sampled` field so the prompt never mislabels a covered
# (evaluated but unmatched) event as one "no rule could evaluate".
REASON_UNCOVERED = "no loaded detection rule covers this channel/event type"
REASON_NAMED_PIPE = (
    "a rule covers this event type and did not match, but it fits the named-pipe discovery advisory pattern"
)
REASON_SERVICE_INSTALL = (
    "a rule covers this event type and did not match, but it is a service installation the rule does not judge"
)

FILENAME_MAX = 500


def create_pending_opinion(db: Session, filename: str, sample_event_ids: list[int]) -> AiOpinion:
    """Synchronous insert (fast -- just a row write, not the LLM call) so
    `POST /ingest` can return `ai_opinion_id` immediately; the slow part
    happens in fill_in_opinion(), scheduled as a background task."""
    opinion = AiOpinion(
        filename=filename if len(filename) <= FILENAME_MAX else filename[: FILENAME_MAX - 1] + "\u2026",
        created_at=datetime.now(timezone.utc),
        status="pending",
        sample_event_ids=sample_event_ids[:MAX_SAMPLE_EVENTS],
    )
    db.add(opinion)
    db.commit()
    db.refresh(opinion)
    return opinion


def _event_summary(event: Event, group_total: int | None, why_sampled: str | None = None) -> dict:
    """The promoted columns (unchanged -- already public via GET /events),
    plus `event_data`: the same flattened Sysmon/Security field dict
    already computed by normalize_event() and already visible to an
    analyst via GET /events/{id}'s raw_json (models/event.py, event_
    service.py) -- not a new field, just no longer withheld from this one
    consumer. Still never the *full* raw_json (the raw XML record) -- that
    boundary is unchanged. `event.process`/`command_line`/`user` stay
    populated only for the event types the normalizer promotes them for
    (Sysmon 1/3/11, Security 4688); `event_data` is what fills in the
    picture for every other event type this path is now reached for.

    `group_total`: the real total count of this event's (channel, event_id)
    group across the whole file (from IngestOutcome.uncovered_breakdown),
    so the model is told "this is 1 of N", not left to assume the sample
    is the whole picture -- mechanical pass-through of an already-computed
    count, not a new derived signal.
    """
    raw_json = event.raw_json or {}
    event_data = raw_json.get("normalized", {}).get("event_data") or {}
    event_type = (
        _SYSMON_EVENT_TYPE_LABELS.get(event.event_id) if canonical_channel(event.channel) == "sysmon" else None
    )
    return {
        "why_sampled": why_sampled,
        "channel": event.channel,
        "event_id": event.event_id,
        # Omitted (not None) for anything outside the known Sysmon set
        # above -- format_event_samples already drops None/""/[] values,
        # so an event type this project doesn't have a real label for
        # simply doesn't get a fabricated one.
        "event_type": event_type,
        "host": event.host,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "process": event.process,
        "command_line": event.command_line,
        "user": event.user,
        "event_data": event_data,
        "group_total_occurrences": group_total,
    }


def _group_totals(uncovered_breakdown: list[UncoveredEventGroup]) -> dict[tuple[str | None, int], int]:
    return {(g.channel, g.event_id): g.count for g in uncovered_breakdown}


def _attack_candidate_ids(chunks: list[dict], min_score: float = MIN_CANDIDATE_SCORE) -> list[str]:
    """Structured ATT&CK candidates, sourced ONLY from retrieved MITRE KB
    chunk metadata (ai/tools/build_kb.py already attaches a real
    technique_id to every mitre_technique chunk) -- never from the LLM's
    own text. This is a read of already-computed retrieval metadata, not a
    new classifier: it can only ever surface a technique this run's
    retrieve() call actually returned, so it is structurally incapable of
    hallucinating one the model wasn't shown."""
    ids: list[str] = []
    for chunk in chunks:
        metadata = chunk.get("metadata") or {}
        if metadata.get("source_type") != _MITRE_TECHNIQUE_SOURCE_TYPE:
            continue
        if float(chunk.get("score") or 0.0) < min_score:
            continue
        technique_id = metadata.get("technique_id")
        if technique_id and technique_id not in ids:
            ids.append(technique_id)
    return ids


def _build_retrieval_query(filename: str, samples: list[dict]) -> str:
    """Mechanical concatenation of already-known field values into a
    semantic-search query -- no new judgment about what's relevant, just
    feeding the retriever more of what's already in each sample.

    Missed until caught by a real end-to-end run: `event_data` was added
    to `_event_summary`'s output but never read here, so for any event
    type the normalizer doesn't promote process/command_line for (which is
    most non-Sysmon-1/3/11, non-Security-4688 telemetry -- BITS, registry,
    network, PowerShell script-block, ...) the query fell back to just the
    filename plus a channel string repeated once per sample, with nothing
    to actually distinguish techniques. On a real BITS-abuse fixture this
    produced a 0.42-0.47 similarity match, pulling in unrelated techniques
    (T1216.001, T1547.010) ahead of the KB's own real T1197 "BITS Jobs"
    chunk -- confirmed present and scoring 0.52-0.58 the moment the query
    actually contains BITS-related terms.
    """
    parts: list[object] = [filename]
    for sample in samples:
        parts.extend([sample.get("channel"), sample.get("process"), sample.get("command_line")])
        event_data = sample.get("event_data")
        if isinstance(event_data, dict):
            parts.extend(v for v in event_data.values() if isinstance(v, str))
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


def fill_in_opinion(
    opinion_id: int,
    filename: str,
    sample_event_ids: list[int],
    matched_rule_titles: list[str] | None = None,
    uncovered_breakdown: list[UncoveredEventGroup] | None = None,
    sample_reasons: dict[int, str] | None = None,
    anomaly_titles: list[str] | None = None,
) -> None:
    db = SessionLocal()
    try:
        events = db.query(Event).filter(Event.id.in_(sample_event_ids)).all() if sample_event_ids else []
        # Reorder to match sample_event_ids's own order (the round-robin
        # selection order from ingest_service.py) -- `Event.id.in_(...)`
        # gives no ordering guarantee of its own, so without this the
        # events actually summarized here could silently differ in order
        # from the ids create_pending_opinion already persisted.
        events_by_id = {e.id: e for e in events}
        ordered_events = [events_by_id[eid] for eid in sample_event_ids if eid in events_by_id]

        group_totals = _group_totals(uncovered_breakdown or [])
        reasons = sample_reasons or {}
        samples = [
            _event_summary(e, group_totals.get((e.channel, e.event_id)), reasons.get(e.id, REASON_UNCOVERED))
            for e in ordered_events[:MAX_SAMPLE_EVENTS]
        ]

        query = _build_retrieval_query(filename, samples)
        chunks = retrieve(query, k=DEFAULT_K)

        reply = generate(
            build_uncovered_opinion_prompt(filename, samples, chunks, matched_rule_titles, anomaly_titles)
        )
        label = extract_assessment_label(reply)
        reply, unknown_ids = annotate_unknown_technique_ids(reply)
        if unknown_ids:
            logger.warning("ai_opinion %d: model cited unknown technique id(s) %s", opinion_id, unknown_ids)
        limitations = extract_uncovered_limitations(reply)

        opinion = db.get(AiOpinion, opinion_id)
        if opinion is None:
            logger.warning("ai_opinion %d not found when filling in", opinion_id)
            return
        opinion.status = "ready"
        opinion.assessment_label = label
        opinion.summary = reply
        opinion.limitations = limitations or None
        # No candidates for a "nothing unusual" verdict: offering techniques
        # next to "nothing stands out" reads as an accusation the opinion
        # itself does not make.
        opinion.attack_candidate_ids = [] if label == "nothing_unusual" else _attack_candidate_ids(chunks)
        db.commit()
    except LLMProviderError as e:
        logger.warning("ai_opinion %d: LLM call failed: %s", opinion_id, e)
        _mark_failed(db, opinion_id, str(e))
    except Exception as e:  # noqa: BLE001 -- a background task must never raise into the void unlogged
        logger.exception("ai_opinion %d: unexpected failure", opinion_id)
        _mark_failed(db, opinion_id, f"internal error while generating the opinion ({type(e).__name__})")
    finally:
        db.close()
