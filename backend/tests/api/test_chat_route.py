"""Day 11 verification (Pair 2): POST /incidents/{id}/chat -- persists the
user message, generates a grounded reply (mocked), persists the assistant
reply, and returns both plus source attribution. `api_client` fixture
(conftest.py) provides the TestClient + in-memory SQLite session.

Runs fully offline -- rag.chat_service.generate_chat_reply is mocked, no
network call and no real LLM_API_KEY is needed or used.
"""

from datetime import datetime, timezone

from app.models.chat_message import ChatMessage
from app.models.incident import Incident
from app.rag.chat_service import ChatReplyResult

SAMPLE_CHUNKS = [
    {
        "chunk_id": "T1059.001-mitre-0",
        "document": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "metadata": {"technique_id": "T1059.001", "technique_name": "PowerShell"},
        "score": 0.81,
    }
]


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


def test_chat_happy_path_persists_both_turns(api_client, monkeypatch):
    client, SessionLocal = api_client
    incident_id = _insert_incident(SessionLocal)

    captured = {}

    def fake_generate_chat_reply(incident, history, message):
        captured["incident"] = incident
        captured["history"] = history
        captured["message"] = message
        return ChatReplyResult(reply="It was a PowerShell execution.", chunks=SAMPLE_CHUNKS)

    monkeypatch.setattr("app.api.routes_chat.generate_chat_reply", fake_generate_chat_reply)

    response = client.post(f"/incidents/{incident_id}/chat", json={"message": "What happened?"})

    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == incident_id
    assert body["role"] == "assistant"
    assert body["content"] == "It was a PowerShell execution."
    assert body["sources"] == SAMPLE_CHUNKS

    assert captured["message"] == "What happened?"
    assert captured["history"] == []
    assert captured["incident"]["technique_id"] == "T1059.001"
    assert captured["incident"]["host"] == "WIN10-ANALYST"

    with SessionLocal() as db:
        rows = (
            db.query(ChatMessage)
            .filter_by(incident_id=incident_id)
            .order_by(ChatMessage.created_at)
            .all()
        )
    assert [r.role for r in rows] == ["user", "assistant"]
    assert rows[0].content == "What happened?"
    assert rows[1].content == "It was a PowerShell execution."


def test_chat_second_turn_includes_prior_history(api_client, monkeypatch):
    client, SessionLocal = api_client
    incident_id = _insert_incident(SessionLocal)

    monkeypatch.setattr(
        "app.api.routes_chat.generate_chat_reply",
        lambda incident, history, message: ChatReplyResult(reply="First answer.", chunks=[]),
    )
    first = client.post(f"/incidents/{incident_id}/chat", json={"message": "First question?"})
    assert first.status_code == 200

    captured = {}

    def fake_second(incident, history, message):
        captured["history"] = history
        return ChatReplyResult(reply="Second answer.", chunks=[])

    monkeypatch.setattr("app.api.routes_chat.generate_chat_reply", fake_second)

    second = client.post(f"/incidents/{incident_id}/chat", json={"message": "Second question?"})
    assert second.status_code == 200

    assert captured["history"] == [
        {"role": "user", "content": "First question?"},
        {"role": "assistant", "content": "First answer."},
    ]


def test_chat_404_when_incident_not_found(api_client):
    client, _ = api_client

    response = client.post("/incidents/999/chat", json={"message": "hi"})

    assert response.status_code == 404
    assert "999" in response.json()["detail"]
