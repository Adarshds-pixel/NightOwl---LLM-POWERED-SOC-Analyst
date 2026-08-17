"""Day 8 verification (Pair 1): POST /ingest now persists a rule match as
an `alerts` row (services/detection_service.py), not just a count on the
response -- extends test_ingest_detection.py's coverage to also query the
alerts table afterward. `api_client` fixture (conftest.py) provides the
TestClient + in-memory SQLite session.
"""

from app.detection.rule_loader import LoadedRule
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


def test_ingest_persists_one_alert_row_per_match(api_client, monkeypatch):
    client, SessionLocal = api_client
    monkeypatch.setattr("app.api.routes_ingest.get_loaded_rules", lambda: [FAKE_RULE])
    monkeypatch.setattr(
        "app.api.routes_ingest.read_records_as_dicts",
        lambda path: iter([_record("1", command_line="powershell.exe -enc AAA"), _record("1")]),
    )

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


def test_ingest_persists_no_alerts_for_benign_events(api_client, monkeypatch):
    client, SessionLocal = api_client
    monkeypatch.setattr("app.api.routes_ingest.get_loaded_rules", lambda: [FAKE_RULE])
    monkeypatch.setattr(
        "app.api.routes_ingest.read_records_as_dicts",
        lambda path: iter([_record("1", command_line="notepad.exe")]),
    )

    response = client.post(
        "/ingest",
        files={"file": ("fake.evtx", b"irrelevant, reader is mocked", "application/octet-stream")},
    )
    assert response.status_code == 200
    assert response.json()["alerts_created"] == 0

    with SessionLocal() as db:
        assert db.query(Alert).count() == 0


def test_ingest_persists_multiple_alerts_for_multiple_matching_events(api_client, monkeypatch):
    client, SessionLocal = api_client
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

    response = client.post(
        "/ingest",
        files={"file": ("fake.evtx", b"irrelevant, reader is mocked", "application/octet-stream")},
    )
    assert response.status_code == 200
    assert response.json()["alerts_created"] == 2

    with SessionLocal() as db:
        assert db.query(Alert).count() == 2
