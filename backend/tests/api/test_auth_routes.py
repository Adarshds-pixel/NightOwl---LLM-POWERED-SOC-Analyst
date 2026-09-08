"""Tests for the single-admin auth system: POST /auth/login, POST
/auth/logout, GET /auth/me (app/api/routes_auth.py), and real enforcement
of require_session_auth (app/core/auth.py) on a protected route.

Deliberately does NOT use the `api_client` fixture from conftest.py --
that fixture overrides require_session_auth to a no-op so every other
route test in this suite can ignore auth entirely (see its docstring).
This file is the one place session auth needs to be genuinely exercised,
not bypassed, so it builds its own TestClient with the override left out.
"""

import bcrypt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.db.base import Base
from app.db.session import get_db
from app.main import app

TEST_USERNAME = "admin"
TEST_PASSWORD = "correct-horse-battery-staple"
TEST_PASSWORD_HASH = bcrypt.hashpw(TEST_PASSWORD.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


@pytest.fixture
def auth_client(monkeypatch):
    """A TestClient wired to a fresh in-memory DB, with a real admin
    credential configured via monkeypatch (independent of whatever is in
    the developer's real .env). require_session_auth is left in its real,
    enforcing state -- unlike api_client, nothing overrides it here.

    Session-cookie signing itself uses whatever SESSION_SECRET_KEY was
    already baked into the app's SessionMiddleware at import time (that
    middleware is constructed once, when app.main is first imported, so
    monkeypatching settings.session_secret_key per-test would have no
    effect on it) -- the repo's .env always carries a real, non-empty
    value, so this is a stable non-issue for tests.
    """
    monkeypatch.setattr(settings, "admin_username", TEST_USERNAME)
    monkeypatch.setattr(settings, "admin_password_hash", TEST_PASSWORD_HASH)
    monkeypatch.setattr(settings, "login_rate_limit_per_minute", 5)

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    def _override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# POST /auth/login
# ---------------------------------------------------------------------------


def test_login_success_returns_username_and_sets_session_cookie(auth_client):
    response = auth_client.post("/auth/login", json={"username": TEST_USERNAME, "password": TEST_PASSWORD})

    assert response.status_code == 200
    assert response.json() == {"username": TEST_USERNAME}
    assert "nightowl_session" in response.cookies


def test_login_wrong_password_is_rejected_with_generic_error(auth_client):
    response = auth_client.post("/auth/login", json={"username": TEST_USERNAME, "password": "not-the-password"})

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials."


def test_login_wrong_username_is_rejected_with_the_same_generic_error(auth_client):
    """The response body must not differ between "wrong password" and
    "wrong username" -- that difference would let an attacker enumerate
    the valid admin username."""
    wrong_password = auth_client.post("/auth/login", json={"username": TEST_USERNAME, "password": "nope"})
    wrong_username = auth_client.post("/auth/login", json={"username": "nobody", "password": "nope"})

    assert wrong_password.status_code == wrong_username.status_code == 401
    assert wrong_password.json() == wrong_username.json() == {"detail": "Invalid credentials."}


def test_login_missing_password_field_returns_422(auth_client):
    response = auth_client.post("/auth/login", json={"username": TEST_USERNAME})

    assert response.status_code == 422


def test_login_empty_credentials_are_rejected(auth_client):
    response = auth_client.post("/auth/login", json={"username": "", "password": ""})

    assert response.status_code == 401


def test_login_never_succeeds_when_no_admin_password_hash_is_configured(auth_client, monkeypatch):
    """A freshly cloned repo with no .env has admin_password_hash == "" --
    login must stay impossible rather than accepting some baked-in
    default credential."""
    monkeypatch.setattr(settings, "admin_password_hash", "")

    response = auth_client.post("/auth/login", json={"username": TEST_USERNAME, "password": TEST_PASSWORD})

    assert response.status_code == 401


def test_login_is_rate_limited_after_repeated_failures(auth_client):
    for _ in range(settings.login_rate_limit_per_minute):
        response = auth_client.post("/auth/login", json={"username": TEST_USERNAME, "password": "wrong"})
        assert response.status_code == 401

    limited = auth_client.post("/auth/login", json={"username": TEST_USERNAME, "password": "wrong"})
    assert limited.status_code == 429

    # A correct password doesn't bypass the throttle once it has tripped.
    still_limited = auth_client.post("/auth/login", json={"username": TEST_USERNAME, "password": TEST_PASSWORD})
    assert still_limited.status_code == 429


# ---------------------------------------------------------------------------
# GET /auth/me
# ---------------------------------------------------------------------------


def test_me_without_a_session_returns_401(auth_client):
    response = auth_client.get("/auth/me")

    assert response.status_code == 401


def test_me_with_a_valid_session_returns_the_username(auth_client):
    auth_client.post("/auth/login", json={"username": TEST_USERNAME, "password": TEST_PASSWORD})

    response = auth_client.get("/auth/me")

    assert response.status_code == 200
    assert response.json() == {"username": TEST_USERNAME}


# ---------------------------------------------------------------------------
# POST /auth/logout
# ---------------------------------------------------------------------------


def test_logout_invalidates_the_session(auth_client):
    auth_client.post("/auth/login", json={"username": TEST_USERNAME, "password": TEST_PASSWORD})
    assert auth_client.get("/auth/me").status_code == 200

    logout_response = auth_client.post("/auth/logout")
    assert logout_response.status_code == 200
    assert logout_response.json() == {"ok": True}

    assert auth_client.get("/auth/me").status_code == 401


def test_logout_without_a_session_still_succeeds(auth_client):
    """Logging out twice, or logging out when never logged in, must not
    error -- clearing an already-empty session is a no-op, not a failure."""
    response = auth_client.post("/auth/logout")

    assert response.status_code == 200


# ---------------------------------------------------------------------------
# require_session_auth enforcement on a real protected route
# ---------------------------------------------------------------------------


def test_protected_route_rejects_a_request_with_no_session(auth_client):
    response = auth_client.get("/incidents")

    assert response.status_code == 401


def test_protected_route_allows_a_request_with_a_valid_session(auth_client):
    auth_client.post("/auth/login", json={"username": TEST_USERNAME, "password": TEST_PASSWORD})

    response = auth_client.get("/incidents")

    assert response.status_code == 200


def test_protected_route_rejects_again_after_logout(auth_client):
    auth_client.post("/auth/login", json={"username": TEST_USERNAME, "password": TEST_PASSWORD})
    assert auth_client.get("/incidents").status_code == 200

    auth_client.post("/auth/logout")

    assert auth_client.get("/incidents").status_code == 401


def test_health_stays_public_with_no_session(auth_client):
    """/health is a liveness probe, deliberately never gated behind
    login -- see main.py, no require_session_auth dependency is attached
    to it."""
    response = auth_client.get("/health")

    assert response.status_code == 200
