"""Day 9 verification (Pair 2): POST /incidents/{id}/explain -- source
attribution + recommended response, built on Day 8's explain_service.
`api_client` fixture (conftest.py) provides the TestClient + in-memory
SQLite session.

Runs fully offline -- explain_service.generate_explanation is mocked, no
network call and no real LLM_API_KEY is needed or used.
"""

from datetime import datetime, timezone

from app.models.incident import Incident
from app.rag.explain_service import ExplanationResult

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


def test_explain_incident_404_when_not_found(api_client):
    client, _ = api_client

    response = client.post("/incidents/999/explain")

    assert response.status_code == 404
    assert "999" in response.json()["detail"]
