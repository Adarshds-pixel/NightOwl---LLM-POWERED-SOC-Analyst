"""Day 13: X-API-Key header auth (app/core/auth.py).

Every test sets `settings.api_key` explicitly via monkeypatch rather than
relying on the ambient default -- a developer's real (gitignored) .env
might have API_KEY set locally for their own manual testing, which would
make a test assuming "disabled by default" flaky depending on whose
machine runs it.
"""

import pytest

from app.core.config import settings


@pytest.fixture(autouse=True)
def _reset_api_key(monkeypatch):
    monkeypatch.setattr(settings, "api_key", "")
    yield


def test_allowed_without_header_when_key_not_configured(api_client):
    client, _ = api_client
    assert client.get("/incidents").status_code == 200


def test_rejects_missing_header_when_key_configured(api_client, monkeypatch):
    monkeypatch.setattr(settings, "api_key", "test-secret")
    client, _ = api_client
    assert client.get("/incidents").status_code == 401


def test_rejects_wrong_key(api_client, monkeypatch):
    monkeypatch.setattr(settings, "api_key", "test-secret")
    client, _ = api_client
    response = client.get("/incidents", headers={"X-API-Key": "wrong"})
    assert response.status_code == 401


def test_allows_correct_key(api_client, monkeypatch):
    monkeypatch.setattr(settings, "api_key", "test-secret")
    client, _ = api_client
    response = client.get("/incidents", headers={"X-API-Key": "test-secret"})
    assert response.status_code == 200


def test_health_bypasses_auth_even_when_key_configured(api_client, monkeypatch):
    monkeypatch.setattr(settings, "api_key", "test-secret")
    client, _ = api_client
    assert client.get("/health").status_code == 200


@pytest.mark.parametrize(
    "method, path",
    [
        ("get", "/mitre/techniques"),
        ("get", "/incidents"),
        ("get", "/incidents/1"),
        ("post", "/incidents/1/chat"),
    ],
)
def test_every_feature_router_requires_the_configured_key(api_client, monkeypatch, method, path):
    monkeypatch.setattr(settings, "api_key", "test-secret")
    client, _ = api_client
    response = getattr(client, method)(path, **({"json": {"message": "hi"}} if method == "post" else {}))
    assert response.status_code == 401


def test_ingest_router_requires_the_configured_key(api_client, monkeypatch):
    """Separate from the parametrized check above -- /ingest needs a
    multipart file, not a JSON body."""
    monkeypatch.setattr(settings, "api_key", "test-secret")
    client, _ = api_client
    response = client.post("/ingest", files={"file": ("sample.evtx", b"irrelevant", "application/octet-stream")})
    assert response.status_code == 401
