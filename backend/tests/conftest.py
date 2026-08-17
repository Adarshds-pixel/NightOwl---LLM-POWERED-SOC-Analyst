"""Shared pytest fixtures for backend/tests/. `api_client` wires the real
FastAPI app to a fresh in-memory SQLite database via a `get_db` dependency
override, so tests/api/* can send real HTTP requests through the actual
app without needing a live Postgres -- extracted from what was previously
near-identical boilerplate duplicated across the ingest route test files.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app


@pytest.fixture
def api_client():
    """Yields (TestClient, sessionmaker) -- the sessionmaker lets a test
    open its own session afterward to inspect rows the request persisted.
    Dependency override is cleared on teardown regardless of pass/fail.
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
    try:
        yield TestClient(app), TestingSessionLocal
    finally:
        app.dependency_overrides.clear()
