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

from pathlib import Path

from app.detection.rule_loader import get_loaded_rules

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "sample_logs" / "real_world_fixtures" / "malicious"


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
    assert len(get_loaded_rules()) == 41

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
    assert alert["rule_title"] == "Suspicious Encoded PowerShell Command"
    assert alert["technique_id"] == "T1059.001"
    assert alert["event"]["command_line"] == "powershell.exe -EncodedCommand aQBlAHgA"
    assert alert["event"]["host"] == "WORKSTATION01"
    # This fixture's records never set ParentImage -- parent_process must
    # be None, not a missing key or an error.
    assert alert["event"]["parent_process"] is None
    # The second ingested record (notepad.exe) shares this alert's host and
    # exact timestamp, and never matched anything itself -- it's real
    # investigative context, not a detection.
    [related] = alert["related_events"]
    assert related["command_line"] == "notepad.exe"
    assert related["id"] != alert["event"]["id"]


def test_sequence_detected_alert_resolves_rule_title_and_technique_through_the_real_api(api_client):
    """The 2-pattern sequence engine's rule_id was never a loaded YAML
    rule (detection/sequences.py), so it needs its own merge into every
    read route that resolves an Alert's rule_id -> human title/technique
    (routes_alerts.py, routes_events.py, routes_incidents.py).
    build_failure_matrix.py already proves the sequence fires and creates
    a real Alert/Incident; this proves the read side of that same alert
    doesn't come back as "Unknown rule" -- not covered by that script,
    which never calls GET /incidents/{id}.

    Uses the real, on-disk Process Herpaderping fixture (unmocked
    `read_records_as_dicts`) end to end through the real HTTP route,
    same pattern as test_ingest_route.py's sysmon_demo.evtx happy path.
    """
    client, _SessionLocal = api_client
    fixture_path = FIXTURES_DIR / "DE_ProcessHerpaderping_Sysmon_11_10_1_7.evtx"

    with open(fixture_path, "rb") as f:
        ingest_response = client.post(
            "/ingest",
            files={"file": (fixture_path.name, f, "application/octet-stream")},
        )

    assert ingest_response.status_code == 200
    ingest_body = ingest_response.json()
    assert ingest_body["alerts_created"] == 1
    assert ingest_body["matched_rule_titles"] == [
        "Process Herpaderping (File Create -> Process Access -> Image Load Chain)"
    ]
    [incident_id] = ingest_body["incident_ids"]

    detail_body = client.get(f"/incidents/{incident_id}").json()
    assert detail_body["mitre_technique_ids"] == ["T1055"]
    [alert] = detail_body["alerts"]
    assert alert["rule_title"] == "Process Herpaderping (File Create -> Process Access -> Image Load Chain)"
    assert alert["technique_id"] == "T1055"
    # Anchored on the concluding ImageLoad(7) event, not the FileCreate(11)
    # that started the chain.
    assert alert["event"]["event_id"] == 7

    alerts_list = client.get("/alerts").json()["alerts"]
    [alert_row] = alerts_list
    assert alert_row["rule_title"] == "Process Herpaderping (File Create -> Process Access -> Image Load Chain)"
    assert alert_row["technique_id"] == "T1055"

    events_list = client.get("/events", params={"alert_only": True}).json()["events"]
    [event_row] = events_list
    assert event_row["rule_title"] == "Process Herpaderping (File Create -> Process Access -> Image Load Chain)"
    assert event_row["technique_id"] == "T1055"


def test_incident_detail_404_for_unknown_id(api_client):
    client, _ = api_client

    response = client.get("/incidents/999")

    assert response.status_code == 404
    assert "999" in response.json()["detail"]
