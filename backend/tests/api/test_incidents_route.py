"""Day 9 verification (Pair 2): POST /incidents/{id}/explain -- source
attribution + recommended response, built on Day 8's explain_service.
`api_client` fixture (conftest.py) provides the TestClient + in-memory
SQLite session.

Day 12 adds a 503-on-LLMProviderError case (core/errors.py's dedicated
handler).

Day 13 (production hardening) adds: the response cache in front of
explain_incident (a repeat call must not re-invoke generate_explanation),
the audit log entry recorded on every explain call, PATCH
/incidents/{id}/status, and GET /incidents/{id}/audit.

Runs fully offline -- explain_service.generate_explanation is mocked, no
network call and no real LLM_API_KEY is needed or used.
"""

from datetime import datetime, timezone

from app.models.audit_log import AuditLog
from app.models.incident import Incident
from app.rag.explain_service import ExplanationResult
from app.rag.llm_client import LLMProviderError

SAMPLE_CHUNKS = [
    {
        "chunk_id": "T1059.001-mitre-0",
        "document": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "metadata": {"technique_id": "T1059.001", "technique_name": "PowerShell"},
        "score": 0.81,
    }
]

SAMPLE_EXPLANATION = (
    "## What happened\nSomething happened.\n\n"
    "## Why it matters\nIt matters.\n\n"
    "## Recommended next steps\n- Isolate the host.\n- Capture memory."
)


def _insert_incident(SessionLocal, **overrides) -> int:
    defaults = {
        "title": "Suspicious PowerShell execution on WIN10-ANALYST",
        "status": "open",
        "severity": "high",
        "mitre_technique_ids": ["T1059.001"],
        "created_at": datetime.now(timezone.utc),
        "host": "WIN10-ANALYST",
    }
    defaults.update(overrides)
    with SessionLocal() as db:
        incident = Incident(**defaults)
        db.add(incident)
        db.commit()
        db.refresh(incident)
        return incident.id


def test_explain_incident_happy_path(api_client, monkeypatch):
    client, SessionLocal = api_client
    incident_id = _insert_incident(SessionLocal)

    captured = {}

    def fake_generate_explanation(incident):
        captured["incident"] = incident
        return ExplanationResult(
            explanation=SAMPLE_EXPLANATION,
            draft=SAMPLE_EXPLANATION,
            critique=None,
            chunks=SAMPLE_CHUNKS,
        )

    monkeypatch.setattr("app.api.routes_incidents.generate_explanation", fake_generate_explanation)

    response = client.post(f"/incidents/{incident_id}/explain")

    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == incident_id
    assert body["explanation"] == SAMPLE_EXPLANATION
    assert body["recommended_response"] == "- Isolate the host.\n- Capture memory."
    assert body["sources"] == SAMPLE_CHUNKS

    assert captured["incident"]["technique_id"] == "T1059.001"
    assert captured["incident"]["severity"] == "high"
    assert captured["incident"]["host"] == "WIN10-ANALYST"
    assert captured["incident"]["technique_ids"] == ["T1059.001"]


def test_explain_incident_recommended_response_excludes_critique(api_client, monkeypatch):
    """When self-critique flags something, `explanation` gets a "Confidence
    check" section appended (see explain_service.generate_explanation) --
    `recommended_response` must still come from the draft only, not bleed in
    the appended critique text."""
    client, SessionLocal = api_client
    incident_id = _insert_incident(SessionLocal)

    explanation_with_critique = (
        f"{SAMPLE_EXPLANATION}\n\n**Confidence check:**\n- The host name is not confirmed by sources."
    )

    monkeypatch.setattr(
        "app.api.routes_incidents.generate_explanation",
        lambda incident: ExplanationResult(
            explanation=explanation_with_critique,
            draft=SAMPLE_EXPLANATION,
            critique="- The host name is not confirmed by sources.",
            chunks=SAMPLE_CHUNKS,
        ),
    )

    response = client.post(f"/incidents/{incident_id}/explain")

    assert response.status_code == 200
    body = response.json()
    assert body["explanation"] == explanation_with_critique
    assert body["recommended_response"] == "- Isolate the host.\n- Capture memory."
    assert "Confidence check" not in body["recommended_response"]


def test_explain_incident_recommended_response_empty_when_heading_missing(api_client, monkeypatch):
    client, SessionLocal = api_client
    incident_id = _insert_incident(SessionLocal)

    monkeypatch.setattr(
        "app.api.routes_incidents.generate_explanation",
        lambda incident: ExplanationResult(
            explanation="no headings here", draft="no headings here", critique=None, chunks=[]
        ),
    )

    response = client.post(f"/incidents/{incident_id}/explain")

    assert response.status_code == 200
    assert response.json()["recommended_response"] == ""


SAMPLE_EXPLANATION_WITH_CONFIDENCE = (
    "## What happened\nSomething happened.\n\n"
    "## Why it matters\nIt matters.\n\n"
    "## Recommended next steps\n- Isolate the host.\n- Capture memory.\n\n"
    "## Confidence breakdown\n- Fact: the host is confirmed.\n- Inference: none.\n- Uncertainty: none."
)


def test_explain_incident_includes_confidence_breakdown(api_client, monkeypatch):
    """pending.md item 5: the explanation's '## Confidence breakdown'
    section is extracted the same mechanical way recommended_response
    already is, and must stop before it (not bleed the later section into
    the earlier one just because both are grabbed from the same draft)."""
    client, SessionLocal = api_client
    incident_id = _insert_incident(SessionLocal)

    monkeypatch.setattr(
        "app.api.routes_incidents.generate_explanation",
        lambda incident: ExplanationResult(
            explanation=SAMPLE_EXPLANATION_WITH_CONFIDENCE,
            draft=SAMPLE_EXPLANATION_WITH_CONFIDENCE,
            critique=None,
            chunks=SAMPLE_CHUNKS,
        ),
    )

    response = client.post(f"/incidents/{incident_id}/explain")

    assert response.status_code == 200
    body = response.json()
    assert body["recommended_response"] == "- Isolate the host.\n- Capture memory."
    assert body["confidence_breakdown"] == "- Fact: the host is confirmed.\n- Inference: none.\n- Uncertainty: none."


def test_explain_incident_confidence_breakdown_empty_when_heading_missing(api_client, monkeypatch):
    client, SessionLocal = api_client
    incident_id = _insert_incident(SessionLocal)

    monkeypatch.setattr(
        "app.api.routes_incidents.generate_explanation",
        lambda incident: ExplanationResult(
            explanation="no headings here", draft="no headings here", critique=None, chunks=[]
        ),
    )

    response = client.post(f"/incidents/{incident_id}/explain")

    assert response.status_code == 200
    assert response.json()["confidence_breakdown"] == ""


def test_explain_incident_404_when_not_found(api_client):
    client, _ = api_client

    response = client.post("/incidents/999/explain")

    assert response.status_code == 404
    assert "999" in response.json()["detail"]


def test_explain_incident_returns_503_on_llm_provider_error(api_client, monkeypatch):
    client, SessionLocal = api_client
    incident_id = _insert_incident(SessionLocal)

    def raise_error(incident):
        raise LLMProviderError("LLM call failed after 2 attempts: boom")

    monkeypatch.setattr("app.api.routes_incidents.generate_explanation", raise_error)

    response = client.post(f"/incidents/{incident_id}/explain")

    assert response.status_code == 503
    assert "boom" in response.json()["detail"]


def test_explain_incident_second_call_served_from_cache(api_client, monkeypatch):
    client, SessionLocal = api_client
    incident_id = _insert_incident(SessionLocal)

    call_count = {"n": 0}

    def fake_generate_explanation(incident):
        call_count["n"] += 1
        return ExplanationResult(
            explanation=SAMPLE_EXPLANATION, draft=SAMPLE_EXPLANATION, critique=None, chunks=SAMPLE_CHUNKS
        )

    monkeypatch.setattr("app.api.routes_incidents.generate_explanation", fake_generate_explanation)

    first = client.post(f"/incidents/{incident_id}/explain")
    second = client.post(f"/incidents/{incident_id}/explain")

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json() == first.json()
    assert call_count["n"] == 1


def test_explain_incident_cache_disabled_always_recomputes(api_client, monkeypatch):
    """settings.response_cache_enabled=False must bypass the cache entirely
    -- every call re-invokes generate_explanation."""
    client, SessionLocal = api_client
    incident_id = _insert_incident(SessionLocal)
    monkeypatch.setattr("app.api.routes_incidents.settings.response_cache_enabled", False)

    call_count = {"n": 0}

    def fake_generate_explanation(incident):
        call_count["n"] += 1
        return ExplanationResult(
            explanation=SAMPLE_EXPLANATION, draft=SAMPLE_EXPLANATION, critique=None, chunks=SAMPLE_CHUNKS
        )

    monkeypatch.setattr("app.api.routes_incidents.generate_explanation", fake_generate_explanation)

    client.post(f"/incidents/{incident_id}/explain")
    client.post(f"/incidents/{incident_id}/explain")

    assert call_count["n"] == 2


def test_explain_incident_records_audit_event(api_client, monkeypatch):
    client, SessionLocal = api_client
    incident_id = _insert_incident(SessionLocal)

    monkeypatch.setattr(
        "app.api.routes_incidents.generate_explanation",
        lambda incident: ExplanationResult(
            explanation=SAMPLE_EXPLANATION, draft=SAMPLE_EXPLANATION, critique=None, chunks=SAMPLE_CHUNKS
        ),
    )

    response = client.post(f"/incidents/{incident_id}/explain")
    assert response.status_code == 200

    with SessionLocal() as db:
        events = db.query(AuditLog).filter_by(entity_id=incident_id, entity_type="incident").all()

    assert len(events) == 1
    assert events[0].action == "explain"
    assert events[0].actor == "system"


def test_update_incident_status_happy_path(api_client):
    client, SessionLocal = api_client
    incident_id = _insert_incident(SessionLocal)

    response = client.patch(f"/incidents/{incident_id}/status", json={"status": "resolved"})

    assert response.status_code == 200
    body = response.json()
    assert body == {"id": incident_id, "status": "resolved"}

    with SessionLocal() as db:
        incident = db.get(Incident, incident_id)
        assert incident.status == "resolved"

        events = db.query(AuditLog).filter_by(entity_id=incident_id, entity_type="incident").all()

    assert len(events) == 1
    assert events[0].action == "status_change"
    assert events[0].actor == "system"
    assert events[0].details == {"from": "open", "to": "resolved"}


def test_update_incident_status_ignores_client_supplied_actor(api_client):
    """The audit actor comes from the server-side session; a request body
    claiming to be someone else must not be able to rewrite the audit log."""
    client, SessionLocal = api_client
    incident_id = _insert_incident(SessionLocal)

    response = client.patch(
        f"/incidents/{incident_id}/status", json={"status": "investigating", "actor": "analyst.jane"}
    )

    assert response.status_code == 200

    with SessionLocal() as db:
        events = db.query(AuditLog).filter_by(entity_id=incident_id, entity_type="incident").all()

    assert events[0].actor == "system"


def test_update_incident_status_rejects_invalid_status(api_client):
    client, SessionLocal = api_client
    incident_id = _insert_incident(SessionLocal)

    response = client.patch(f"/incidents/{incident_id}/status", json={"status": "bogus"})

    assert response.status_code == 400
    assert "bogus" in response.json()["detail"]

    with SessionLocal() as db:
        incident = db.get(Incident, incident_id)
        assert incident.status == "open"


def test_update_incident_status_404_when_not_found(api_client):
    client, _ = api_client

    response = client.patch("/incidents/999/status", json={"status": "resolved"})

    assert response.status_code == 404
    assert "999" in response.json()["detail"]


def test_get_incident_audit_log_returns_events_in_order(api_client):
    client, SessionLocal = api_client
    incident_id = _insert_incident(SessionLocal)

    client.patch(f"/incidents/{incident_id}/status", json={"status": "investigating"})
    client.patch(f"/incidents/{incident_id}/status", json={"status": "resolved"})

    response = client.get(f"/incidents/{incident_id}/audit")

    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == incident_id
    assert body["count"] == 2
    assert [e["details"] for e in body["events"]] == [
        {"from": "open", "to": "investigating"},
        {"from": "investigating", "to": "resolved"},
    ]


def test_get_incident_audit_log_404_when_not_found(api_client):
    client, _ = api_client

    response = client.get("/incidents/999/audit")

    assert response.status_code == 404
    assert "999" in response.json()["detail"]


def test_explain_incident_audit_actor_is_the_caller(api_client, monkeypatch):
    """The audit actor comes from the authenticated caller, not a fixed
    "system" placeholder."""
    client, SessionLocal = api_client
    incident_id = _insert_incident(SessionLocal)
    monkeypatch.setattr("app.core.auth.settings.api_key", "test-key")
    monkeypatch.setattr(
        "app.api.routes_incidents.generate_explanation",
        lambda incident: ExplanationResult(
            explanation=SAMPLE_EXPLANATION, draft=SAMPLE_EXPLANATION, critique=None, chunks=SAMPLE_CHUNKS
        ),
    )

    response = client.post(f"/incidents/{incident_id}/explain", headers={"X-API-Key": "test-key"})
    assert response.status_code == 200

    with SessionLocal() as db:
        event = db.query(AuditLog).filter_by(entity_id=incident_id, action="explain").one()
    assert event.actor == "api-key"
