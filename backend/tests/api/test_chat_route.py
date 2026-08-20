"""Day 11 verification (Pair 2): POST /incidents/{id}/chat -- persists the
user message, generates a grounded reply (mocked), persists the assistant
reply, and returns both plus source attribution. `api_client` fixture
(conftest.py) provides the TestClient + in-memory SQLite session.

Day 12 adds: GET /incidents/{id}/chat (history) and a 503-on-LLMProviderError
case for the POST route (core/errors.py's dedicated handler).

Runs fully offline -- rag.chat_service.generate_chat_reply is mocked, no
network call and no real LLM_API_KEY is needed or used.
"""

from datetime import datetime, timezone

from app.models.chat_message import ChatMessage
from app.models.incident import Incident
from app.rag.chat_service import ChatReplyResult
from app.rag.llm_client import LLMProviderError

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


def test_chat_returns_503_on_llm_provider_error(api_client, monkeypatch):
    client, SessionLocal = api_client
    incident_id = _insert_incident(SessionLocal)

    def raise_error(incident, history, message):
        raise LLMProviderError("LLM call failed after 2 attempts: boom")

    monkeypatch.setattr("app.api.routes_chat.generate_chat_reply", raise_error)

    response = client.post(f"/incidents/{incident_id}/chat", json={"message": "hi"})

    assert response.status_code == 503
    assert "boom" in response.json()["detail"]


def test_get_chat_history_empty_for_new_incident(api_client):
    client, SessionLocal = api_client
    incident_id = _insert_incident(SessionLocal)

    response = client.get(f"/incidents/{incident_id}/chat")

    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == incident_id
    assert body["messages"] == []
    assert body["count"] == 0


def test_get_chat_history_returns_messages_in_order(api_client, monkeypatch):
    client, SessionLocal = api_client
    incident_id = _insert_incident(SessionLocal)

    monkeypatch.setattr(
        "app.api.routes_chat.generate_chat_reply",
        lambda incident, history, message: ChatReplyResult(reply="First answer.", chunks=SAMPLE_CHUNKS),
    )
    client.post(f"/incidents/{incident_id}/chat", json={"message": "First question?"})

    response = client.get(f"/incidents/{incident_id}/chat")

    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == incident_id
    assert body["count"] == 2
    assert [m["role"] for m in body["messages"]] == ["user", "assistant"]
    assert body["messages"][0]["content"] == "First question?"
    assert body["messages"][1]["content"] == "First answer."
    assert all("id" in m and "created_at" in m for m in body["messages"])


def test_get_chat_history_404_when_incident_not_found(api_client):
    client, _ = api_client

    response = client.get("/incidents/999/chat")

    assert response.status_code == 404
    assert "999" in response.json()["detail"]
