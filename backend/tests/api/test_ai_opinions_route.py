"""GET /ai-opinions/{id} -- the read-only poll endpoint in isolation (see
routes_ai_opinions.py). Previously only exercised incidentally through
POST /ingest (test_ingest_route.py); this file covers the route on its
own, including the 404 case that had no dedicated test.
"""

from datetime import datetime, timezone

from app.models.ai_opinion import AiOpinion
from app.services import ai_opinion_service


def test_get_ai_opinion_404_for_unknown_id(api_client):
    client, _SessionLocal = api_client
    response = client.get("/ai-opinions/999999")
    assert response.status_code == 404
    assert "999999" in response.json()["detail"]


def test_get_ai_opinion_returns_pending_row(api_client):
    client, SessionLocal = api_client
    with SessionLocal() as db:
        opinion = ai_opinion_service.create_pending_opinion(db, "mystery.evtx", sample_event_ids=[1, 2])
        opinion_id = opinion.id

    response = client.get(f"/ai-opinions/{opinion_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == opinion_id
    assert body["filename"] == "mystery.evtx"
    assert body["status"] == "pending"
    assert body["assessment_label"] is None
    assert body["summary"] is None
    assert body["sample_event_ids"] == [1, 2]
    assert body["limitations"] is None
    assert body["attack_candidate_ids"] is None


def test_get_ai_opinion_returns_structured_fields_once_ready(api_client):
    client, SessionLocal = api_client
    with SessionLocal() as db:
        opinion = AiOpinion(
            filename="mystery.evtx",
            created_at=datetime.now(timezone.utc),
            status="ready",
            assessment_label="worth_reviewing",
            summary="Something looks off.\n\n## Assessment: Worth reviewing\n\n## Limitations\n- Small sample.",
            sample_event_ids=[1],
            limitations="- Small sample.",
            attack_candidate_ids=["T1059.001"],
        )
        db.add(opinion)
        db.commit()
        db.refresh(opinion)
        opinion_id = opinion.id

    response = client.get(f"/ai-opinions/{opinion_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["limitations"] == "- Small sample."
    assert body["attack_candidate_ids"] == ["T1059.001"]


def test_retry_reruns_only_a_failed_opinion(api_client, monkeypatch):
    client, SessionLocal = api_client
    calls = []
    monkeypatch.setattr(
        "app.api.routes_ai_opinions.fill_in_opinion",
        lambda opinion_id, filename, sample_ids, *rest: calls.append((opinion_id, filename, sample_ids)),
    )
    with SessionLocal() as db:
        opinion = ai_opinion_service.create_pending_opinion(db, "quota.evtx", sample_event_ids=[3, 4])
        opinion.status = "failed"
        opinion.error = "AI request failed: the AI provider's rate limit was reached"
        db.commit()
        opinion_id = opinion.id

    response = client.post(f"/ai-opinions/{opinion_id}/retry")

    assert response.status_code == 202
    assert response.json()["status"] == "pending"
    assert response.json()["error"] is None
    assert calls == [(opinion_id, "quota.evtx", [3, 4])]


def test_retry_refuses_an_opinion_that_is_not_failed(api_client, monkeypatch):
    client, SessionLocal = api_client
    monkeypatch.setattr("app.api.routes_ai_opinions.fill_in_opinion", lambda *a, **k: None)
    with SessionLocal() as db:
        opinion_id = ai_opinion_service.create_pending_opinion(db, "fine.evtx", sample_event_ids=[1]).id

    assert client.post(f"/ai-opinions/{opinion_id}/retry").status_code == 409
    assert client.post("/ai-opinions/999999/retry").status_code == 404
