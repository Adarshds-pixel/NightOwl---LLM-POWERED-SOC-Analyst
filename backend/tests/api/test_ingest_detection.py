"""Day 7 verification (Pair 1): POST /ingest runs each normalized event
through the detection engine and reports matches -- persisting them as
`alerts` rows is Day 8's job, not this one. `api_client` fixture
(conftest.py) provides the TestClient + in-memory SQLite session.
"""

from app.detection.rule_loader import LoadedRule

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
                "TimeCreated": {"@SystemTime": "2026-08-16T10:00:00.000000+00:00"},
                "Computer": "WORKSTATION01",
            },
            "EventData": {"Data": data},
        }
    }


def test_ingest_reports_rule_matches(api_client, monkeypatch):
    client, _ = api_client
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
    assert body["rule_matches"] == 1
    assert body["matched_rule_titles"] == ["Fake Encoded PowerShell Rule"]


def test_ingest_reports_no_matches_for_benign_events(api_client, monkeypatch):
    client, _ = api_client
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
    body = response.json()
    assert body["rule_matches"] == 0
    assert body["matched_rule_titles"] == []
