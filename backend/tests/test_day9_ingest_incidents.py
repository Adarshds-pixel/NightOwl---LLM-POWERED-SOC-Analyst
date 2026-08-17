"""Day 9 verification (Pair 1): POST /ingest now groups matching alerts
into incidents (services/incident_service.py), not just persisting bare
alerts (Day 8) -- extends test_day8_ingest_alerts.py's TestClient +
in-memory-SQLite pattern to also query the incidents table.
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
from app.models.incident import Incident

FAKE_RULE = LoadedRule(
    rule_id="fake-rule-1",
    title="Fake Encoded PowerShell Rule",
    level="high",
    category="process_creation",
    detections={"selection": {"CommandLine|contains": "-enc"}},
    condition="selection",
    yaml_path="<test>",
    technique_id="T1059.001",
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


def _record(event_id, command_line=None, computer="WORKSTATION01"):
    data = [] if command_line is None else [{"@Name": "CommandLine", "#text": command_line}]
    return {
        "Event": {
            "System": {
                "EventID": event_id,
                "TimeCreated": {"@SystemTime": "2026-08-19T10:00:00.000000+00:00"},
                "Computer": computer,
            },
            "EventData": {"Data": data},
        }
    }


def test_matching_alerts_on_same_host_link_to_one_incident(monkeypatch):
    monkeypatch.setattr("app.api.routes_ingest.get_loaded_rules", lambda: [FAKE_RULE])
    monkeypatch.setattr(
        "app.api.routes_ingest.read_records_as_dicts",
        lambda path: iter(
            [
                _record("1", command_line="powershell.exe -enc AAA", computer="WORKSTATION01"),
                _record("1", command_line="powershell.exe -enc BBB", computer="WORKSTATION01"),
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
        body = response.json()
        assert body["alerts_created"] == 2
        assert len(body["incident_ids"]) == 1

        with SessionLocal() as db:
            incident = db.query(Incident).one()
            assert incident.host == "WORKSTATION01"
            assert incident.mitre_technique_ids == ["T1059.001"]

            alerts = db.query(Alert).all()
            assert len(alerts) == 2
            assert all(a.incident_id == incident.id for a in alerts)
    finally:
        app.dependency_overrides.clear()


def test_matching_alerts_on_different_hosts_get_separate_incidents(monkeypatch):
    monkeypatch.setattr("app.api.routes_ingest.get_loaded_rules", lambda: [FAKE_RULE])
    monkeypatch.setattr(
        "app.api.routes_ingest.read_records_as_dicts",
        lambda path: iter(
            [
                _record("1", command_line="powershell.exe -enc AAA", computer="WORKSTATION01"),
                _record("1", command_line="powershell.exe -enc BBB", computer="WORKSTATION02"),
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
        assert len(response.json()["incident_ids"]) == 2

        with SessionLocal() as db:
            assert db.query(Incident).count() == 2
    finally:
        app.dependency_overrides.clear()


def test_benign_events_create_no_incidents(monkeypatch):
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
        assert response.json()["incident_ids"] == []

        with SessionLocal() as db:
            assert db.query(Incident).count() == 0
    finally:
        app.dependency_overrides.clear()
