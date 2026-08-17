"""Day 8 verification (Pair 1): POST /ingest now persists a rule match as
an `alerts` row (services/detection_service.py), not just a count on the
response -- extends test_day7_ingest_detection.py's TestClient +
in-memory-SQLite pattern to also query the alerts table afterward.
"""

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.detection.rule_loader import LoadedRule
from app.main import app
from app.models.alert import Alert
from app.models.event import Event

FAKE_RULE = LoadedRule(
    rule_id="fake-rule-1",
    title="Fake Encoded PowerShell Rule",
    level="high",
    category="process_creation",
    detections={"selection": {"CommandLine|contains": "-enc"}},
    condition="selection",
    yaml_path="<test>",
)


def _client_and_sessionmaker():
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
    return TestClient(app), TestingSessionLocal


def _record(event_id, command_line=None):
    data = [] if command_line is None else [{"@Name": "CommandLine", "#text": command_line}]
    return {
        "Event": {
            "System": {
                "EventID": event_id,
                "TimeCreated": {"@SystemTime": "2026-08-18T10:00:00.000000+00:00"},
                "Computer": "WORKSTATION01",
            },
            "EventData": {"Data": data},
        }
    }


def test_ingest_persists_one_alert_row_per_match(monkeypatch):
    monkeypatch.setattr("app.api.routes_ingest.get_loaded_rules", lambda: [FAKE_RULE])
    monkeypatch.setattr(
        "app.api.routes_ingest.read_records_as_dicts",
        lambda path: iter([_record("1", command_line="powershell.exe -enc AAA"), _record("1")]),
    )

    client, SessionLocal = _client_and_sessionmaker()
    try:
        response = client.post(
            "/ingest",
            files={"file": ("fake.evtx", b"irrelevant, reader is mocked", "application/octet-stream")},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["alerts_created"] == 1

        with SessionLocal() as db:
            alerts = db.query(Alert).all()
            assert len(alerts) == 1
            assert alerts[0].rule_id == "fake-rule-1"
            assert alerts[0].severity == "high"

            matched_event = db.query(Event).filter(Event.command_line.like("%-enc%")).one()
            assert alerts[0].event_id == matched_event.id
    finally:
        app.dependency_overrides.clear()


def test_ingest_persists_no_alerts_for_benign_events(monkeypatch):
    monkeypatch.setattr("app.api.routes_ingest.get_loaded_rules", lambda: [FAKE_RULE])
    monkeypatch.setattr(
        "app.api.routes_ingest.read_records_as_dicts",
        lambda path: iter([_record("1", command_line="notepad.exe")]),
    )

    client, SessionLocal = _client_and_sessionmaker()
    try:
        response = client.post(
            "/ingest",
            files={"file": ("fake.evtx", b"irrelevant, reader is mocked", "application/octet-stream")},
        )
        assert response.status_code == 200
        assert response.json()["alerts_created"] == 0

        with SessionLocal() as db:
            assert db.query(Alert).count() == 0
    finally:
        app.dependency_overrides.clear()


def test_ingest_persists_multiple_alerts_for_multiple_matching_events(monkeypatch):
    monkeypatch.setattr("app.api.routes_ingest.get_loaded_rules", lambda: [FAKE_RULE])
    monkeypatch.setattr(
        "app.api.routes_ingest.read_records_as_dicts",
        lambda path: iter(
            [
                _record("1", command_line="powershell.exe -enc AAA"),
                _record("1", command_line="powershell.exe -enc BBB"),
            ]
        ),
    )

    client, SessionLocal = _client_and_sessionmaker()
    try:
        response = client.post(
            "/ingest",
            files={"file": ("fake.evtx", b"irrelevant, reader is mocked", "application/octet-stream")},
        )
        assert response.status_code == 200
        assert response.json()["alerts_created"] == 2

        with SessionLocal() as db:
            assert db.query(Alert).count() == 2
    finally:
        app.dependency_overrides.clear()
