"""GET /events -- the raw event-timeline endpoint behind the Logs page.
Same in-memory-SQLite api_client pattern as test_incidents_list_route.py.
"""

from datetime import datetime, timedelta, timezone

from app.models.alert import Alert
from app.models.event import Event

BASE_TIME = datetime(2026, 8, 25, 12, 0, 0, tzinfo=timezone.utc)


def _insert_event(db, **overrides) -> int:
    fields = dict(host="HOST-A", timestamp=BASE_TIME, event_id=1, process="cmd.exe", command_line=None, user=None)
    fields.update(overrides)
    event = Event(raw_json={"raw": {}, "normalized": {}}, **fields)
    db.add(event)
    db.flush()
    db.commit()
    return event.id


def _insert_alert(db, event_id: int, **overrides) -> None:
    fields = dict(rule_id="rule-1", matched_at=BASE_TIME, severity="high")
    fields.update(overrides)
    db.add(Alert(event_id=event_id, **fields))
    db.commit()


def test_default_limit_is_50(api_client):
    client, SessionLocal = api_client
    with SessionLocal() as db:
        for i in range(3):
            _insert_event(db, timestamp=BASE_TIME + timedelta(minutes=i))

    response = client.get("/events")

    assert response.status_code == 200
    body = response.json()
    assert body["limit"] == 50
    assert body["offset"] == 0
    assert body["count"] == 3
    assert body["total"] == 3


def test_event_with_no_alert_reports_is_alert_false(api_client):
    client, SessionLocal = api_client
    with SessionLocal() as db:
        _insert_event(db)

    response = client.get("/events")

    row = response.json()["events"][0]
    assert row["is_alert"] is False
    assert row["severity"] is None
    assert row["rule_title"] is None


def test_event_with_alert_reports_severity_and_rule_title(api_client):
    client, SessionLocal = api_client
    with SessionLocal() as db:
        event_id = _insert_event(db)
        # Real seed rule id/title from backend/app/detection/rules/suspicious_encoded_powershell.yml
        _insert_alert(db, event_id, rule_id="5b1f3a2e-6c1e-4f6a-9b8e-2f8b1a9d6e11", severity="critical")

    response = client.get("/events")

    row = response.json()["events"][0]
    assert row["is_alert"] is True
    assert row["severity"] == "critical"
    assert row["rule_title"] == "Suspicious Encoded PowerShell Command"
    assert row["technique_id"] == "T1059.001"


def test_alert_only_true_filters_to_alerted_events_only(api_client):
    client, SessionLocal = api_client
    with SessionLocal() as db:
        alerted_id = _insert_event(db, host="HOST-A")
        _insert_event(db, host="HOST-B")
        _insert_alert(db, alerted_id)

    response = client.get("/events", params={"alert_only": True})

    body = response.json()
    assert body["count"] == 1
    assert body["events"][0]["host"] == "HOST-A"


def test_host_filter_restricts_results(api_client):
    client, SessionLocal = api_client
    with SessionLocal() as db:
        _insert_event(db, host="HOST-A")
        _insert_event(db, host="HOST-B")

    response = client.get("/events", params={"host": "HOST-B"})

    body = response.json()
    assert body["count"] == 1
    assert body["events"][0]["host"] == "HOST-B"


def test_limit_and_offset_page_through_distinct_results(api_client):
    client, SessionLocal = api_client
    with SessionLocal() as db:
        for i in range(5):
            _insert_event(db, timestamp=BASE_TIME + timedelta(minutes=i))

    page1 = client.get("/events", params={"limit": 2, "offset": 0}).json()
    page2 = client.get("/events", params={"limit": 2, "offset": 2}).json()

    ids_page1 = [e["id"] for e in page1["events"]]
    ids_page2 = [e["id"] for e in page2["events"]]
    assert len(ids_page1) == 2
    assert len(ids_page2) == 2
    assert set(ids_page1).isdisjoint(ids_page2)
    assert page1["total"] == 5
    assert page2["total"] == 5


def test_limit_above_cap_returns_422(api_client):
    client, _ = api_client

    response = client.get("/events", params={"limit": 500})

    assert response.status_code == 422


def test_alert_row_carries_its_incident_id(api_client):
    """Alert rows link back to the investigation they were grouped into,
    so the Alerts page can route a detection to its incident."""
    client, SessionLocal = api_client
    with SessionLocal() as db:
        from app.models.incident import Incident

        incident = Incident(
            title="Suspicious activity on HOST-A",
            status="open",
            severity="high",
            host="HOST-A",
            mitre_technique_ids=["T1059.001"],
            created_at=BASE_TIME,
        )
        db.add(incident)
        db.flush()
        event_id = _insert_event(db)
        db.add(Alert(event_id=event_id, rule_id="rule-1", matched_at=BASE_TIME, severity="high", incident_id=incident.id))
        db.commit()
        expected_incident_id = incident.id

    row = client.get("/events").json()["events"][0]

    assert row["incident_id"] == expected_incident_id


def test_ordinary_event_has_no_incident_id(api_client):
    client, SessionLocal = api_client
    with SessionLocal() as db:
        _insert_event(db)

    assert client.get("/events").json()["events"][0]["incident_id"] is None


def test_q_matches_command_line_case_insensitively(api_client):
    client, SessionLocal = api_client
    with SessionLocal() as db:
        _insert_event(db, process="powershell.exe", command_line="powershell -EncodedCommand ZQBjAGgA")
        _insert_event(db, process="cmd.exe", command_line="dir C:/Users", timestamp=BASE_TIME + timedelta(minutes=1))

    body = client.get("/events", params={"q": "encodedcommand"}).json()

    assert body["total"] == 1
    assert body["events"][0]["process"] == "powershell.exe"


def test_q_matches_host_and_user(api_client):
    client, SessionLocal = api_client
    with SessionLocal() as db:
        _insert_event(db, host="WKS-42", user="administrator")
        _insert_event(db, host="HOST-B", user="svc_backup", timestamp=BASE_TIME + timedelta(minutes=1))

    assert client.get("/events", params={"q": "wks"}).json()["total"] == 1
    assert client.get("/events", params={"q": "svc_"}).json()["total"] == 1


def test_q_is_combined_with_other_filters(api_client):
    client, SessionLocal = api_client
    with SessionLocal() as db:
        alerted = _insert_event(db, process="mshta.exe")
        _insert_alert(db, alerted)
        _insert_event(db, process="mshta.exe", timestamp=BASE_TIME + timedelta(minutes=1))

    body = client.get("/events", params={"q": "mshta", "alert_only": "true"}).json()

    assert body["total"] == 1


def test_event_detail_returns_raw_payload(api_client):
    client, SessionLocal = api_client
    with SessionLocal() as db:
        event = Event(
            host="HOST-A",
            timestamp=BASE_TIME,
            event_id=1,
            process="powershell.exe",
            command_line="powershell -enc AAA",
            user="administrator",
            raw_json={"raw": {"EventID": 1, "ParentImage": "explorer.exe"}, "normalized": {"host": "HOST-A"}},
        )
        db.add(event)
        db.commit()
        event_id = event.id

    response = client.get(f"/events/{event_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == event_id
    assert body["raw"]["ParentImage"] == "explorer.exe"
    assert body["normalized"]["host"] == "HOST-A"
    assert body["is_alert"] is False


def test_event_detail_includes_alert_enrichment(api_client):
    client, SessionLocal = api_client
    with SessionLocal() as db:
        event_id = _insert_event(db)
        _insert_alert(db, event_id, rule_id="5b1f3a2e-6c1e-4f6a-9b8e-2f8b1a9d6e11", severity="critical")

    body = client.get(f"/events/{event_id}").json()

    assert body["is_alert"] is True
    assert body["severity"] == "critical"
    assert body["rule_title"] == "Suspicious Encoded PowerShell Command"


def test_unknown_event_id_is_404(api_client):
    client, _ = api_client

    response = client.get("/events/424242")

    assert response.status_code == 404
    assert response.json()["detail"] == "event 424242 not found"
