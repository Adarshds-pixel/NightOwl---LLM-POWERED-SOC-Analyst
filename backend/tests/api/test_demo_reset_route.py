"""POST /demo/reset -- the only remaining route under /demo/* now that Live
Replay has been removed (kept: the one-shot "Run demo" pipeline, which reuses
POST /ingest directly and needs no dedicated route of its own).
"""

from app.core.config import settings


def test_reset_when_idle_returns_deleted_counts(api_client):
    client, _ = api_client
    response = client.post("/demo/reset")
    assert response.status_code == 200
    body = response.json()
    assert set(body["deleted"]) == {"ai_opinions", "chat_messages", "audit_log", "alerts", "incidents", "events"}
    assert all(count == 0 for count in body["deleted"].values())


def test_demo_mode_disabled_returns_403(api_client, monkeypatch):
    client, _ = api_client
    monkeypatch.setattr(settings, "demo_mode_enabled", False)

    response = client.post("/demo/reset")
    assert response.status_code == 403
