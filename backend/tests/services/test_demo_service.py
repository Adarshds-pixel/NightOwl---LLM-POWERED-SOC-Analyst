"""services/demo_service.py -- full data reset between demo runs."""

from datetime import datetime, timezone

from app.models.alert import Alert
from app.models.audit_log import AuditLog
from app.models.chat_message import ChatMessage
from app.models.event import Event
from app.models.incident import Incident
from app.services.demo_service import reset_demo_data

BASE_TIME = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)


def _seed_all_tables(db) -> None:
    event = Event(
        host="Nightowl",
        timestamp=BASE_TIME,
        event_id=1,
        process="powershell.exe",
        command_line=None,
        user=None,
        raw_json={"raw": {}, "normalized": {}},
    )
    db.add(event)
    db.flush()

    incident = Incident(
        title="Demo incident",
        status="open",
        severity="high",
        host="Nightowl",
        mitre_technique_ids=["T1059.001"],
        created_at=BASE_TIME,
    )
    db.add(incident)
    db.flush()

    db.add(Alert(event_id=event.id, rule_id="rule-1", matched_at=BASE_TIME, severity="high", incident_id=incident.id))
    db.add(ChatMessage(incident_id=incident.id, role="user", content="what happened?", created_at=BASE_TIME))
    db.add(AuditLog(entity_type="incident", entity_id=incident.id, action="explain", actor="system", created_at=BASE_TIME))
    db.commit()


def test_reset_empties_every_operational_table(api_client):
    _client, SessionLocal = api_client
    with SessionLocal() as db:
        _seed_all_tables(db)

        deleted = reset_demo_data(db)

        assert deleted == {
            "ai_opinions": 0,
            "chat_messages": 1,
            "audit_log": 1,
            "alerts": 1,
            "incidents": 1,
            "events": 1,
        }
        assert db.query(Event).count() == 0
        assert db.query(Alert).count() == 0
        assert db.query(Incident).count() == 0
        assert db.query(ChatMessage).count() == 0
        assert db.query(AuditLog).count() == 0


def test_reset_on_an_already_empty_database_returns_zeros(api_client):
    _client, SessionLocal = api_client
    with SessionLocal() as db:
        deleted = reset_demo_data(db)
        assert all(count == 0 for count in deleted.values())


def test_reset_leaves_the_database_usable_afterwards(api_client):
    """A reset must not orphan the session or leave a half-open transaction
    that breaks the next real write -- exactly what the replay does
    immediately after calling this."""
    _client, SessionLocal = api_client
    with SessionLocal() as db:
        _seed_all_tables(db)
        reset_demo_data(db)

        db.add(Event(host="H", timestamp=BASE_TIME, event_id=1, raw_json={}))
        db.commit()
        assert db.query(Event).count() == 1
