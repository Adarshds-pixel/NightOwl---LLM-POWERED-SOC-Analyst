"""Day 11 verification (Pair 2): services/chat_service.py -- `chat_messages`
persistence (add_message/list_messages), independent of the RAG
retrieve->answer pipeline (rag/chat_service.py, tested separately in
tests/rag/test_chat_service.py). Uses an in-memory SQLite engine, same
pattern as services/test_incident_service.py.
"""

from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.base import Base
from app.models.incident import Incident
from app.services.chat_service import add_message, list_messages


def _engine():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine


def _insert_incident(db: Session) -> int:
    incident = Incident(
        title="Suspicious PowerShell execution on WIN10-ANALYST",
        status="open",
        severity="high",
        mitre_technique_ids=["T1059.001"],
        created_at=datetime.now(timezone.utc),
        host="WIN10-ANALYST",
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident.id


def test_add_message_persists_role_and_content():
    with Session(_engine()) as db:
        incident_id = _insert_incident(db)

        message = add_message(db, incident_id, role="user", content="What happened?")

        assert message.id is not None
        assert message.incident_id == incident_id
        assert message.role == "user"
        assert message.content == "What happened?"
        assert message.created_at is not None


def test_list_messages_returns_oldest_first_for_matching_incident():
    with Session(_engine()) as db:
        incident_id = _insert_incident(db)
        other_incident_id = _insert_incident(db)

        add_message(db, incident_id, role="user", content="First question?")
        add_message(db, incident_id, role="assistant", content="First answer.")
        add_message(db, other_incident_id, role="user", content="Unrelated question.")

        messages = list_messages(db, incident_id)

        assert [m.content for m in messages] == ["First question?", "First answer."]
        assert all(m.incident_id == incident_id for m in messages)


def test_list_messages_empty_for_incident_with_no_messages():
    with Session(_engine()) as db:
        incident_id = _insert_incident(db)

        assert list_messages(db, incident_id) == []
