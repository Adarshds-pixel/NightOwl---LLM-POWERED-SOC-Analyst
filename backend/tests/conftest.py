"""Shared pytest fixtures for backend/tests/. `api_client` wires the real
FastAPI app to a fresh in-memory SQLite database via a `get_db` dependency
override, so tests/api/* can send real HTTP requests through the actual
app without needing a live Postgres -- extracted from what was previously
near-identical boilerplate duplicated across the ingest route test files.
"""

import getpass
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.auth import require_session_auth
from app.core.rate_limit import reset_rate_limiter
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.rag import cache as response_cache


def pytest_configure(config):
    """Windows dev-machine workaround: on some machines,
    %LOCALAPPDATA%\\Temp\\pytest-of-<user> ends up with an ACL that even its
    own owning account can't read (confirmed via icacls/Get-Acl, both fail
    with "Access is denied" -- needs admin elevation to fix at the OS
    level). pytest's tmp_path/tmp_path_factory fixtures then fail at setup
    with PermissionError, before any test code runs, on every test that
    uses them.

    Detect that specific failure mode and redirect --basetemp to a fresh
    sibling directory instead of requiring elevation. No-op if the default
    already works, or if --basetemp was already passed explicitly.
    """
    if config.option.basetemp is not None:
        return

    default_base = Path(tempfile.gettempdir()) / f"pytest-of-{getpass.getuser()}"
    try:
        default_base.mkdir(parents=True, exist_ok=True)
        next(default_base.iterdir(), None)
    except OSError:
        fallback = Path(tempfile.gettempdir()) / "nightowl-pytest-tmp"
        fallback.mkdir(parents=True, exist_ok=True)
        config.option.basetemp = fallback


@pytest.fixture(autouse=True)
def _clear_response_cache():
    """Day 13: rag/cache.py's dicts live for the whole pytest process, but
    api_client below gives every test a fresh in-memory DB whose
    autoincrement incident ids restart at 1 -- without this, a cached
    result from one test file would leak into an unrelated test that
    happens to reuse the same incident id."""
    response_cache.clear()
    yield
    response_cache.clear()


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """`app.main.app` is a module-level singleton reused by every test in the
    session, and Starlette's TestClient reports every request's client as the
    same fixed ("testclient", 50000) tuple -- so without a reset between
    tests, rate-limit token consumption in one test would leak into later,
    unrelated tests as spurious 429s.
    """
    reset_rate_limiter()
    yield
    reset_rate_limiter()


@pytest.fixture
def api_client():
    """Yields (TestClient, sessionmaker) -- the sessionmaker lets a test
    open its own session afterward to inspect rows the request persisted.
    Dependency override is cleared on teardown regardless of pass/fail.

    `require_session_auth` is overridden to a no-op here, the same way
    `require_api_key` is effectively a no-op by default (settings.api_key
    is "" unless a test opts in via monkeypatch, see tests/core/test_auth.py).
    This fixture predates admin login entirely and every test using it is
    about its own route's behavior, not about auth -- real enforcement of
    require_session_auth is covered separately in
    tests/api/test_auth_routes.py, which builds its own TestClient without
    this override.
    """
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
    app.dependency_overrides[require_session_auth] = lambda: None
    try:
        yield TestClient(app), TestingSessionLocal
    finally:
        app.dependency_overrides.clear()
