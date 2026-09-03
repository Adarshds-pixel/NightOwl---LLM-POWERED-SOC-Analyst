"""GET /alerts -- the real "every rule match" feed behind the Alerts page.

Same in-memory-SQLite api_client pattern as test_events_route.py. The core
thing this file exists to prove: an event matched by two rules must produce
two rows/count here, unlike GET /events?alert_only=true which collapses it
to one -- this was the root cause of the Alerts page total disagreeing with
an incident's own evidence-list length.
"""

from datetime import datetime, timedelta, timezone

from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import Incident

BASE_TIME = datetime(2026, 8, 25, 12, 0, 0, tzinfo=timezone.utc)


def _insert_event(db, **overrides) -> int:
    fields = dict(host="HOST-A", timestamp=BASE_TIME, event_id=1, process="cmd.exe", command_line=None, user=None)
    fields.update(overrides)
    event = Event(raw_json={"raw": {}, "normalized": {}}, **fields)
    db.add(event)
    db.flush()
    db.commit()
    return event.id


def _insert_alert(db, event_id: int, **overrides) -> int:
    fields = dict(rule_id="rule-1", matched_at=BASE_TIME, severity="high")
    fields.update(overrides)
    alert = Alert(event_id=event_id, **fields)
    db.add(alert)
    db.commit()
    return alert.id


def test_default_limit_is_50(api_client):
    client, SessionLocal = api_client
    with SessionLocal() as db:
        event_id = _insert_event(db)
        for i in range(3):
            _insert_alert(db, event_id, matched_at=BASE_TIME + timedelta(minutes=i), rule_id=f"rule-{i}")

    response = client.get("/alerts")

    assert response.status_code == 200
    body = response.json()
    assert body["limit"] == 50
    assert body["offset"] == 0
    assert body["count"] == 3
    assert body["total"] == 3


def test_one_event_matched_by_two_rules_produces_two_rows(api_client):
    """The regression test for the bug: GET /events?alert_only=true collapses
    a double-matched event to one row, undercounting the Alerts page total
    against the true number of alerts (and against an incident's own
    evidence list, which is never collapsed). GET /alerts must not do that.
    """
    client, SessionLocal = api_client
    with SessionLocal() as db:
        event_id = _insert_event(db)
        _insert_alert(db, event_id, rule_id="rule-a", severity="critical")
        _insert_alert(db, event_id, rule_id="rule-b", severity="high")

    body = client.get("/alerts").json()

    assert body["total"] == 2
    assert body["count"] == 2
    event_ids = {row["id"] for row in body["alerts"]}
    assert event_ids == {event_id}, "both rows should point at the same underlying event"
    alert_ids = {row["alert_id"] for row in body["alerts"]}
    assert len(alert_ids) == 2, "each row must carry its own distinct alert_id"


def test_alert_row_carries_its_incident_id(api_client):
    client, SessionLocal = api_client
    with SessionLocal() as db:
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

    row = client.get("/alerts").json()["alerts"][0]

    assert row["incident_id"] == expected_incident_id


def test_host_filter_restricts_results(api_client):
    client, SessionLocal = api_client
    with SessionLocal() as db:
        a = _insert_event(db, host="HOST-A")
        b = _insert_event(db, host="HOST-B", timestamp=BASE_TIME + timedelta(minutes=1))
        _insert_alert(db, a)
        _insert_alert(db, b)

    body = client.get("/alerts", params={"host": "HOST-B"}).json()

    assert body["count"] == 1
    assert body["alerts"][0]["host"] == "HOST-B"


def test_severity_filter_restricts_results(api_client):
    client, SessionLocal = api_client
    with SessionLocal() as db:
        event_id = _insert_event(db)
        _insert_alert(db, event_id, rule_id="rule-a", severity="critical")
        _insert_alert(db, event_id, rule_id="rule-b", severity="low")

    body = client.get("/alerts", params={"severity": "critical"}).json()

    assert body["total"] == 1
    assert body["alerts"][0]["severity"] == "critical"


def test_limit_and_offset_page_through_distinct_results(api_client):
    client, SessionLocal = api_client
    with SessionLocal() as db:
        event_id = _insert_event(db)
        for i in range(5):
            _insert_alert(db, event_id, matched_at=BASE_TIME + timedelta(minutes=i), rule_id=f"rule-{i}")

    page1 = client.get("/alerts", params={"limit": 2, "offset": 0}).json()
    page2 = client.get("/alerts", params={"limit": 2, "offset": 2}).json()

    ids_page1 = [a["alert_id"] for a in page1["alerts"]]
    ids_page2 = [a["alert_id"] for a in page2["alerts"]]
    assert len(ids_page1) == 2
    assert len(ids_page2) == 2
    assert set(ids_page1).isdisjoint(ids_page2)
    assert page1["total"] == 5
    assert page2["total"] == 5


def test_limit_above_cap_returns_422(api_client):
    client, _ = api_client

    response = client.get("/alerts", params={"limit": 500})

    assert response.status_code == 422


def test_q_matches_command_line_case_insensitively(api_client):
    client, SessionLocal = api_client
    with SessionLocal() as db:
        a = _insert_event(db, process="powershell.exe", command_line="powershell -EncodedCommand ZQBjAGgA")
        b = _insert_event(db, process="cmd.exe", command_line="dir C:/Users", timestamp=BASE_TIME + timedelta(minutes=1))
        _insert_alert(db, a)
        _insert_alert(db, b)

    body = client.get("/alerts", params={"q": "encodedcommand"}).json()

    assert body["total"] == 1
    assert body["alerts"][0]["process"] == "powershell.exe"


def test_rule_title_resolved_from_loaded_rules(api_client):
    client, SessionLocal = api_client
    with SessionLocal() as db:
        event_id = _insert_event(db)
        # Real seed rule id/title from backend/app/detection/rules/suspicious_encoded_powershell.yml
        _insert_alert(db, event_id, rule_id="5b1f3a2e-6c1e-4f6a-9b8e-2f8b1a9d6e11", severity="critical")

    row = client.get("/alerts").json()["alerts"][0]

    assert row["rule_title"] == "Suspicious Encoded PowerShell Command"
    assert row["technique_id"] == "T1059.001"


def test_alert_total_matches_sum_of_per_incident_evidence(api_client):
    """End-to-end proof the bug is fixed: an incident with N alerts and the
    system-wide alerts total must never disagree, the way the Alerts page
    (18) and an incident's evidence tab (22) did before this endpoint
    existed.
    """
    client, SessionLocal = api_client
    with SessionLocal() as db:
        incident = Incident(
            title="Multi-alert incident",
            status="open",
            severity="critical",
            host="HOST-A",
            mitre_technique_ids=["T1059.001"],
            created_at=BASE_TIME,
        )
        db.add(incident)
        db.flush()
        event_a = _insert_event(db)
        event_b = _insert_event(db, timestamp=BASE_TIME + timedelta(minutes=1))
        db.add(Alert(event_id=event_a, rule_id="rule-a", matched_at=BASE_TIME, severity="high", incident_id=incident.id))
        db.add(Alert(event_id=event_a, rule_id="rule-b", matched_at=BASE_TIME, severity="critical", incident_id=incident.id))
        db.add(Alert(event_id=event_b, rule_id="rule-c", matched_at=BASE_TIME, severity="high", incident_id=incident.id))
        db.commit()
        incident_id = incident.id

    alerts_total = client.get("/alerts").json()["total"]
    incident_evidence_count = len(client.get(f"/incidents/{incident_id}").json()["alerts"])

    assert alerts_total == 3
    assert incident_evidence_count == 3
    assert alerts_total == incident_evidence_count
