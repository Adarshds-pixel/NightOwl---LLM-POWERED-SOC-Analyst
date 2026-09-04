"""services/ai_opinion_service.py -- LLM second-opinion generation for
uncovered events. Mirrors test_chat_service.py's mocking style: patches
`retrieve`/`generate` at their app.services.ai_opinion_service import
location, no network or LLM call. Advisory-only boundary (never an
Alert/Incident, never blocks the caller) is the thing under test here --
retrieval/prompt-rendering correctness is rag/test_*.py's job.
"""

from datetime import datetime, timezone

from app.models.ai_opinion import AiOpinion
from app.models.event import Event
from app.rag.llm_client import LLMProviderError
from app.services import ai_opinion_service

SAMPLE_CHUNKS = [
    {
        "chunk_id": "T1003-mitre-0",
        "document": "Adversaries may attempt to dump credentials.",
        "metadata": {"technique_id": "T1003"},
        "score": 0.7,
    }
]


def _make_event(db, *, channel="Security", event_id=4624, process=None) -> Event:
    event = Event(
        host="DC1",
        timestamp=datetime(2026, 8, 30, 9, 0, 0, tzinfo=timezone.utc),
        event_id=event_id,
        channel=channel,
        process=process,
        command_line=None,
        user=None,
        raw_json={},
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def test_create_pending_opinion_inserts_pending_row(api_client):
    _client, SessionLocal = api_client
    with SessionLocal() as db:
        opinion = ai_opinion_service.create_pending_opinion(db, "mystery.evtx", sample_event_ids=[1, 2])

        assert opinion.id is not None
        assert opinion.status == "pending"
        assert opinion.filename == "mystery.evtx"
        assert opinion.sample_event_ids == [1, 2]
        assert opinion.assessment_label is None
        assert opinion.summary is None


def test_create_pending_opinion_caps_sample_event_ids(api_client):
    _client, SessionLocal = api_client
    with SessionLocal() as db:
        many_ids = list(range(1, 20))
        opinion = ai_opinion_service.create_pending_opinion(db, "big.evtx", sample_event_ids=many_ids)

        assert len(opinion.sample_event_ids) == ai_opinion_service.MAX_SAMPLE_EVENTS


def test_fill_in_opinion_success_updates_status_and_label(api_client, monkeypatch):
    _client, SessionLocal = api_client
    # fill_in_opinion opens its OWN fresh SessionLocal() (by design -- a
    # background task's request-scoped session may already be closed by
    # the time it runs). In production there's only one real database, so
    # the module-level SessionLocal it imports is correct as-is; in tests,
    # that name must be patched to the fixture's in-memory engine the same
    # way retrieve/generate are patched at their use-site module.
    monkeypatch.setattr(ai_opinion_service, "SessionLocal", SessionLocal)
    with SessionLocal() as db:
        event = _make_event(db)
        event_id = event.id
        opinion = ai_opinion_service.create_pending_opinion(db, "mystery.evtx", sample_event_ids=[event_id])
        opinion_id = opinion.id

    monkeypatch.setattr(ai_opinion_service, "retrieve", lambda query, k: SAMPLE_CHUNKS)
    monkeypatch.setattr(
        ai_opinion_service, "generate", lambda messages: "Nothing here looks unusual.\n\n## Assessment: Nothing unusual noted"
    )

    ai_opinion_service.fill_in_opinion(opinion_id, "mystery.evtx", [event_id])

    with SessionLocal() as db:
        opinion = db.get(AiOpinion, opinion_id)
        assert opinion.status == "ready"
        assert opinion.assessment_label == "nothing_unusual"
        assert "Nothing here looks unusual" in opinion.summary
        assert opinion.error is None


def test_fill_in_opinion_llm_failure_marks_status_failed_with_error(api_client, monkeypatch):
    _client, SessionLocal = api_client
    monkeypatch.setattr(ai_opinion_service, "SessionLocal", SessionLocal)
    with SessionLocal() as db:
        event = _make_event(db)
        event_id = event.id
        opinion = ai_opinion_service.create_pending_opinion(db, "mystery.evtx", sample_event_ids=[event_id])
        opinion_id = opinion.id

    monkeypatch.setattr(ai_opinion_service, "retrieve", lambda query, k: [])

    def raise_error(messages):
        raise LLMProviderError("quota exceeded")

    monkeypatch.setattr(ai_opinion_service, "generate", raise_error)

    ai_opinion_service.fill_in_opinion(opinion_id, "mystery.evtx", [event_id])

    with SessionLocal() as db:
        opinion = db.get(AiOpinion, opinion_id)
        assert opinion.status == "failed"
        assert "quota exceeded" in opinion.error
        assert opinion.assessment_label is None


def test_fill_in_opinion_never_creates_an_alert_or_incident(api_client, monkeypatch):
    """The hard constraint: an AI opinion must never manifest as a real
    detection, however it resolves."""
    _client, SessionLocal = api_client
    monkeypatch.setattr(ai_opinion_service, "SessionLocal", SessionLocal)
    with SessionLocal() as db:
        event = _make_event(db)
        event_id = event.id
        opinion = ai_opinion_service.create_pending_opinion(db, "mystery.evtx", sample_event_ids=[event_id])
        opinion_id = opinion.id

    monkeypatch.setattr(ai_opinion_service, "retrieve", lambda query, k: [])
    monkeypatch.setattr(
        ai_opinion_service, "generate", lambda messages: "This looks concerning.\n\n## Assessment: Worth reviewing"
    )

    ai_opinion_service.fill_in_opinion(opinion_id, "mystery.evtx", [event_id])

    with SessionLocal() as db:
        from app.models.alert import Alert
        from app.models.incident import Incident

        assert db.query(Alert).count() == 0
        assert db.query(Incident).count() == 0
        opinion = db.get(AiOpinion, opinion_id)
        assert opinion.assessment_label == "worth_reviewing"


def test_event_summary_never_includes_raw_json_fields():
    event = Event(
        id=1,
        host="DC1",
        timestamp=datetime(2026, 8, 30, 9, 0, 0, tzinfo=timezone.utc),
        event_id=4624,
        channel="Security",
        process="cmd.exe",
        command_line="cmd.exe /c whoami",
        user="alice",
        raw_json={"secret_internal_field": "should never appear"},
    )

    summary = ai_opinion_service._event_summary(event)

    assert set(summary.keys()) == {"channel", "event_id", "host", "timestamp", "process", "command_line", "user"}
    assert "secret_internal_field" not in str(summary)
