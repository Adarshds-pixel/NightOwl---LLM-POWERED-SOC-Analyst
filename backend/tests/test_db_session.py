"""Verification for app/db/session.py's get_db() dependency: an exception
propagating through a request must roll back whatever the failed request's
session had queued, not just close() it -- see get_db()'s own comment for
why close() alone doesn't guarantee a rollback happened.

Uses its own in-memory SQLite engine (monkeypatched onto app.db.session's
module-level SessionLocal) rather than the shared api_client fixture, since
that fixture overrides get_db entirely for API tests and so never exercises
the real generator's exception-handling path.

SQLite's `:memory:` database is scoped to a single connection; SQLAlchemy's
default pool for it (SingletonThreadPool) keeps one connection per thread,
so multiple Session objects built from the same engine within one test
(single-threaded) all see the same in-memory data -- this is what lets
these tests open a second, independent session to verify what did or
didn't actually get committed.
"""

from datetime import datetime

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.db import session as db_session
from app.db.base import Base
from app.db.session import get_db
from app.models.incident import Incident


@pytest.fixture
def in_memory_session_factory(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    monkeypatch.setattr(db_session, "SessionLocal", factory)
    return factory


def _make_incident(**overrides):
    fields = dict(
        title="test incident",
        status="open",
        severity="high",
        severity_score=4,
        mitre_technique_ids=[],
        host="WORKSTATION01",
        created_at=datetime(2026, 1, 1),
    )
    fields.update(overrides)
    return Incident(**fields)


def test_get_db_rolls_back_uncommitted_writes_on_exception(in_memory_session_factory):
    gen = get_db()
    db = next(gen)
    db.add(_make_incident(title="never committed"))
    db.flush()  # visible within this session/transaction, not yet committed

    with pytest.raises(RuntimeError, match="simulated route failure"):
        gen.throw(RuntimeError("simulated route failure"))

    with in_memory_session_factory() as verify_db:
        assert verify_db.scalars(select(Incident)).all() == []


def test_get_db_calls_rollback_on_exception(in_memory_session_factory, monkeypatch):
    gen = get_db()
    db = next(gen)
    calls = []
    monkeypatch.setattr(db, "rollback", lambda: calls.append(1))

    with pytest.raises(RuntimeError):
        gen.throw(RuntimeError("boom"))

    assert calls == [1]


def test_get_db_closes_the_session_after_an_exception(in_memory_session_factory, monkeypatch):
    gen = get_db()
    db = next(gen)
    close_calls = []
    monkeypatch.setattr(db, "close", lambda: close_calls.append(1))

    with pytest.raises(RuntimeError):
        gen.throw(RuntimeError("boom"))

    assert close_calls == [1]


def test_get_db_commits_normally_on_the_happy_path(in_memory_session_factory):
    gen = get_db()
    db = next(gen)
    db.add(_make_incident(title="committed normally"))
    db.commit()
    with pytest.raises(StopIteration):
        next(gen)

    with in_memory_session_factory() as verify_db:
        titles = [i.title for i in verify_db.scalars(select(Incident)).all()]
    assert titles == ["committed normally"]
