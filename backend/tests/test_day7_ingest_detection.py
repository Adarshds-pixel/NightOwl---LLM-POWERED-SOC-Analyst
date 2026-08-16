"""Day 7 verification (Pair 1): POST /ingest runs each normalized event
through the detection engine and reports matches -- persisting them as
`alerts` rows is Day 8's job, not this one.
"""

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.detection.rule_loader import LoadedRule
from app.main import app

FAKE_RULE = LoadedRule(
    rule_id="fake-rule-1",
    title="Fake Encoded PowerShell Rule",
    level="high",
    category="process_creation",
    detections={"selection": {"CommandLine|contains": "-enc"}},
    condition="selection",
    yaml_path="<test>",
)


def _client():
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
    return TestClient(app)


def _record(event_id, command_line=None):
    data = [] if command_line is None else [{"@Name": "CommandLine", "#text": command_line}]
    return {
        "Event": {
            "System": {
                "EventID": event_id,
                "TimeCreated": {"@SystemTime": "2026-08-16T10:00:00.000000+00:00"},
                "Computer": "WORKSTATION01",
            },
            "EventData": {"Data": data},
        }
    }


def test_ingest_reports_rule_matches(monkeypatch):
    monkeypatch.setattr("app.api.routes_ingest.get_loaded_rules", lambda: [FAKE_RULE])
    monkeypatch.setattr(
        "app.api.routes_ingest.read_records_as_dicts",
        lambda path: iter([_record("1", command_line="powershell.exe -enc AAA"), _record("1")]),
    )

    client = _client()
    try:
        response = client.post(
            "/ingest",
            files={"file": ("fake.evtx", b"irrelevant, reader is mocked", "application/octet-stream")},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["rule_matches"] == 1
        assert body["matched_rule_titles"] == ["Fake Encoded PowerShell Rule"]
    finally:
        app.dependency_overrides.clear()


def test_ingest_reports_no_matches_for_benign_events(monkeypatch):
    monkeypatch.setattr("app.api.routes_ingest.get_loaded_rules", lambda: [FAKE_RULE])
    monkeypatch.setattr(
        "app.api.routes_ingest.read_records_as_dicts",
        lambda path: iter([_record("1", command_line="notepad.exe")]),
    )

    client = _client()
    try:
        response = client.post(
            "/ingest",
            files={"file": ("fake.evtx", b"irrelevant, reader is mocked", "application/octet-stream")},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["rule_matches"] == 0
        assert body["matched_rule_titles"] == []
    finally:
        app.dependency_overrides.clear()
