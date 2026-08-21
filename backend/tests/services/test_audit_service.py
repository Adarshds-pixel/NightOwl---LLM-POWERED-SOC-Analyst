"""Day 13 verification (Pair 2): services/audit_service.py -- records
who/when for incident status changes and explain/chat calls. Uses an
in-memory SQLite engine, same pattern as services/test_incident_service.py.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.base import Base
from app.services.audit_service import record_event, list_events


def _engine():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine


def test_record_event_defaults_actor_to_system():
    with Session(_engine()) as db:
        entry = record_event(db, entity_type="incident", entity_id=1, action="explain")

        assert entry.id is not None
        assert entry.entity_type == "incident"
        assert entry.entity_id == 1
        assert entry.action == "explain"
        assert entry.actor == "system"
        assert entry.details is None


def test_record_event_accepts_explicit_actor_and_details():
    with Session(_engine()) as db:
        entry = record_event(
            db,
            entity_type="incident",
            entity_id=1,
            action="status_change",
            actor="analyst.jane",
            details={"from": "open", "to": "resolved"},
        )

        assert entry.actor == "analyst.jane"
        assert entry.details == {"from": "open", "to": "resolved"}


def test_list_events_returns_oldest_first_for_matching_entity():
    with Session(_engine()) as db:
        record_event(db, entity_type="incident", entity_id=1, action="explain")
        record_event(db, entity_type="incident", entity_id=1, action="chat")
        record_event(db, entity_type="incident", entity_id=2, action="explain")

        events = list_events(db, entity_type="incident", entity_id=1)

        assert [e.action for e in events] == ["explain", "chat"]
        assert all(e.entity_id == 1 for e in events)


def test_list_events_empty_when_no_events_recorded():
    with Session(_engine()) as db:
        assert list_events(db, entity_type="incident", entity_id=999) == []
