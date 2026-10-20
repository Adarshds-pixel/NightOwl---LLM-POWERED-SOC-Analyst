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
from app.core.auth import CSRF_HEADER
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
    client = TestClient(app, headers={CSRF_HEADER: "1"})
    client.session_factory = TestingSessionLocal
    try:
        yield client
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


# ---------------------------------------------------------------------------
# Production-readiness hardening
# ---------------------------------------------------------------------------


def _login(client):
    response = client.post("/auth/login", json={"username": TEST_USERNAME, "password": TEST_PASSWORD})
    assert response.status_code == 200
    return response


def test_copied_cookie_stops_working_after_logout(auth_client):
    """Logout revokes the server-side session row, so a cookie captured
    before logout (and replayed afterwards) is rejected -- the signed cookie
    alone is no longer sufficient."""
    _login(auth_client)
    stolen = auth_client.cookies.get("nightowl_session")
    assert auth_client.post("/auth/logout").status_code == 200

    auth_client.cookies.set("nightowl_session", stolen)
    assert auth_client.get("/auth/me").status_code == 401
    assert auth_client.get("/incidents").status_code == 401


def test_successful_logins_do_not_spend_the_failed_login_budget(auth_client):
    for _ in range(8):
        _login(auth_client)
        auth_client.post("/auth/logout")


def test_overlong_password_is_a_401_not_a_500(auth_client):
    response = auth_client.post("/auth/login", json={"username": TEST_USERNAME, "password": "x" * 500})
    assert response.status_code == 401


def test_malformed_password_hash_is_a_401_not_a_500(auth_client, monkeypatch):
    monkeypatch.setattr(settings, "admin_password_hash", "not-a-bcrypt-hash")
    response = auth_client.post("/auth/login", json={"username": TEST_USERNAME, "password": TEST_PASSWORD})
    assert response.status_code == 401


def test_state_changing_request_without_csrf_header_is_rejected(auth_client):
    _login(auth_client)
    bare = TestClient(app)
    bare.cookies = auth_client.cookies
    response = bare.patch("/incidents/1/status", json={"status": "resolved"})
    assert response.status_code == 403


def test_unauthenticated_upload_is_rejected_before_the_body_is_read(auth_client):
    response = auth_client.post(
        "/ingest", files={"file": ("x.evtx", b"x" * 1000, "application/octet-stream")}
    )
    assert response.status_code == 401


def test_readiness_is_public_and_checks_the_database(auth_client):
    response = auth_client.get("/readyz")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_readiness_reports_503_when_the_database_is_unreachable(auth_client):
    class _DeadSession:
        def execute(self, *_args, **_kwargs):
            raise OSError("connection refused")

    app.dependency_overrides[get_db] = lambda: _DeadSession()

    response = auth_client.get("/readyz")

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}


def _auth_audit(client) -> list[tuple[str, str]]:
    from app.models.audit_log import AuditLog

    with client.session_factory() as db:
        rows = db.query(AuditLog).filter(AuditLog.entity_type == "auth").order_by(AuditLog.id).all()
        return [(row.action, row.actor) for row in rows]


def test_login_success_failure_and_logout_are_audited(auth_client):
    auth_client.post("/auth/login", json={"username": TEST_USERNAME, "password": "wrong"})
    _login(auth_client)
    auth_client.post("/auth/logout")

    assert _auth_audit(auth_client) == [
        ("login_failed", TEST_USERNAME),
        ("login_success", TEST_USERNAME),
        ("logout", TEST_USERNAME),
    ]


def test_failed_login_with_an_unknown_username_never_stores_what_was_typed(auth_client):
    """A password typed into the username box must not end up in the audit log."""
    auth_client.post("/auth/login", json={"username": "hunter2-my-password", "password": "x"})

    assert _auth_audit(auth_client) == [("login_failed", "unknown")]


def test_throttled_login_attempts_are_audited(auth_client):
    for _ in range(settings.login_rate_limit_per_minute):
        auth_client.post("/auth/login", json={"username": TEST_USERNAME, "password": "wrong"})
    assert auth_client.post("/auth/login", json={"username": TEST_USERNAME, "password": "wrong"}).status_code == 429

    assert _auth_audit(auth_client)[-1] == ("login_throttled", TEST_USERNAME)


def test_logout_without_a_session_writes_no_audit_row(auth_client):
    auth_client.post("/auth/logout")

    assert _auth_audit(auth_client) == []


def test_api_key_grants_headless_access_when_configured(auth_client, monkeypatch):
    monkeypatch.setattr(settings, "api_key", "k" * 40)
    assert auth_client.get("/incidents").status_code == 401
    assert auth_client.get("/incidents", headers={"X-API-Key": "k" * 40}).status_code == 200
