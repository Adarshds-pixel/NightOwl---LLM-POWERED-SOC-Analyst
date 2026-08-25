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
