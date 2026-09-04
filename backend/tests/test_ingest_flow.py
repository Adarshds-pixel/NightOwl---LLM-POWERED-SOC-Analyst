"""Day 12 verification (Pair 1): "end-to-end integration test (sample file
in, incidents+techniques out)" -- the one test in the suite that exercises
the real pipeline top to bottom: the real 15 on-disk detection rules (not a
FAKE_RULE list, unlike every other ingest test), real detection + severity
scoring + incident grouping, then the real Day 12 `GET /incidents` and
`GET /incidents/{id}` endpoints, resolving a real MITRE technique from the
locally cached dataset (`data/mitre/enterprise-attack.json`, already
downloaded -- see mitre/loader.py). `api_client` fixture (conftest.py)
provides the TestClient + in-memory SQLite session.

Only `read_records_as_dicts` is mocked (same pattern as
tests/api/test_ingest_incidents.py) -- a real EVTX file isn't needed to
prove the rest of the pipeline is wired correctly end to end.
"""

from app.detection.rule_loader import get_loaded_rules


def _record(event_id, command_line, computer="WORKSTATION01"):
    return {
        "Event": {
            "System": {
                "EventID": event_id,
                "TimeCreated": {"@SystemTime": "2026-08-19T10:00:00.000000+00:00"},
                "Computer": computer,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
            },
            "EventData": {"Data": [{"@Name": "CommandLine", "#text": command_line}, {"@Name": "Image", "#text": "C:\\Windows\\System32\\powershell.exe"}]},
        }
    }


def test_sample_file_in_incidents_and_techniques_out(api_client, monkeypatch):
    client, SessionLocal = api_client

    # Sanity check: this test is only meaningful against the real, full
    # rule set -- fail loudly if that ever drifts instead of silently
    # passing against fewer rules.
    assert len(get_loaded_rules()) == 29

    monkeypatch.setattr(
        "app.api.routes_ingest.read_records_as_dicts",
        lambda path: iter(
            [_record("1", "powershell.exe -EncodedCommand aQBlAHgA"), _record("1", "notepad.exe")]
        ),
    )

    ingest_response = client.post(
        "/ingest",
        files={"file": ("sample.evtx", b"irrelevant, reader is mocked", "application/octet-stream")},
    )
    assert ingest_response.status_code == 200
    ingest_body = ingest_response.json()
    assert ingest_body["alerts_created"] == 1
    assert ingest_body["matched_rule_titles"] == ["Suspicious Encoded PowerShell Command"]
    assert len(ingest_body["incident_ids"]) == 1
    incident_id = ingest_body["incident_ids"][0]

    list_response = client.get("/incidents")
    assert list_response.status_code == 200
    list_body = list_response.json()
    assert list_body["count"] == 1
    [incident_summary] = list_body["incidents"]
    assert incident_summary["id"] == incident_id
    assert incident_summary["host"] == "WORKSTATION01"
    assert incident_summary["mitre_technique_ids"] == ["T1059.001"]

    filtered_response = client.get("/incidents", params={"severity": incident_summary["severity"]})
    assert filtered_response.json()["count"] == 1
    assert client.get("/incidents", params={"severity": "no-such-severity"}).json()["count"] == 0

    detail_response = client.get(f"/incidents/{incident_id}")
    assert detail_response.status_code == 200
    detail_body = detail_response.json()
    assert detail_body["mitre_technique_ids"] == ["T1059.001"]
    assert detail_body["techniques"] == [
        {"id": "T1059.001", "name": "PowerShell", "tactics": ["execution"]}
    ]
    [alert] = detail_body["alerts"]
    assert alert["rule_id"]
    assert alert["event"]["command_line"] == "powershell.exe -EncodedCommand aQBlAHgA"
    assert alert["event"]["host"] == "WORKSTATION01"


def test_incident_detail_404_for_unknown_id(api_client):
    client, _ = api_client

    response = client.get("/incidents/999")

    assert response.status_code == 404
    assert "999" in response.json()["detail"]
