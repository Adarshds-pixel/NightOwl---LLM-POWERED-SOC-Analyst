"""GET /rules + GET /rules/{id} -- the read-only detection rule set behind
the Rules Engine page. Same in-memory-SQLite api_client pattern as
test_events_route.py.

These assert against the *real* rule files in
backend/app/detection/rules/, not fixtures: the endpoint's whole purpose
is reporting what actually loaded, so a test double would defeat it.
"""

from datetime import datetime, timedelta, timezone

from app.detection.rule_loader import get_loaded_rules
from app.models.alert import Alert
from app.models.event import Event

# Real seed rule from backend/app/detection/rules/suspicious_encoded_powershell.yml
ENCODED_PS_RULE_ID = "5b1f3a2e-6c1e-4f6a-9b8e-2f8b1a9d6e11"


def _insert_alert(db, rule_id: str, matched_at: datetime, severity: str = "high") -> None:
    event = Event(
        host="HOST-A",
        timestamp=matched_at,
        event_id=1,
        process="powershell.exe",
        command_line=None,
        user=None,
        raw_json={"raw": {}, "normalized": {}},
    )
    db.add(event)
    db.flush()
    db.add(Alert(event_id=event.id, rule_id=rule_id, matched_at=matched_at, severity=severity))
    db.commit()


def test_lists_every_loaded_rule(api_client):
    client, _ = api_client

    response = client.get("/rules")

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == body["total"] == len(get_loaded_rules())
    assert body["total"] > 0


def test_rule_carries_yaml_metadata(api_client):
    client, _ = api_client

    rules = client.get("/rules").json()["rules"]
    rule = next(r for r in rules if r["rule_id"] == ENCODED_PS_RULE_ID)

    assert rule["title"] == "Suspicious Encoded PowerShell Command"
    assert rule["technique_id"] == "T1059.001"
    assert rule["level"] == "high"
    assert rule["category"] == "process_creation"
    assert "execution" in rule["tactics"]
    assert rule["description"].startswith("Detects PowerShell process creation")
    assert rule["filename"] == "suspicious_encoded_powershell.yml"
    assert rule["selections"] == ["selection"]
    assert rule["condition"] == "selection"
    assert rule["enabled"] is True


def test_rule_with_no_alerts_reports_zero_activity(api_client):
    client, _ = api_client

    rule = client.get("/rules").json()["rules"][0]

    assert rule["match_count"] == 0
    assert rule["matches_24h"] == 0
    assert rule["last_triggered"] is None


def test_activity_counts_come_from_the_alerts_table(api_client):
    client, SessionLocal = api_client
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        _insert_alert(db, ENCODED_PS_RULE_ID, now - timedelta(minutes=5))
        _insert_alert(db, ENCODED_PS_RULE_ID, now - timedelta(hours=2))
        # Older than the 24h window: counted in match_count, not matches_24h.
        _insert_alert(db, ENCODED_PS_RULE_ID, now - timedelta(days=3))

    rules = client.get("/rules").json()["rules"]
    rule = next(r for r in rules if r["rule_id"] == ENCODED_PS_RULE_ID)

    assert rule["match_count"] == 3
    assert rule["matches_24h"] == 2
    assert rule["last_triggered"] is not None


def test_activity_window_anchors_to_dataset_not_wall_clock(api_client):
    """The actual bug this test guards: real-world EVTX samples this
    project ingests are dated 2019-2021 (their own historical event time,
    per ingest_service.py's matched_at=None docstring), not "now". If
    matches_24h were computed against real wall-clock time, it would
    permanently read 0 for every historical import regardless of how
    tightly clustered the alerts actually are -- exactly the "Triggered
    24h" KPI showing nothing after ingesting real files.
    """
    client, SessionLocal = api_client
    historical_now = datetime(2019, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
    with SessionLocal() as db:
        _insert_alert(db, ENCODED_PS_RULE_ID, historical_now - timedelta(minutes=5))
        _insert_alert(db, ENCODED_PS_RULE_ID, historical_now - timedelta(hours=2))
        # Older than 24h before the dataset's own latest alert: counted in
        # match_count, not matches_24h -- same rule as the wall-clock test.
        _insert_alert(db, ENCODED_PS_RULE_ID, historical_now - timedelta(days=3))

    rules = client.get("/rules").json()["rules"]
    rule = next(r for r in rules if r["rule_id"] == ENCODED_PS_RULE_ID)

    assert rule["match_count"] == 3
    assert rule["matches_24h"] == 2


def test_filters_by_technique_level_and_category(api_client):
    client, _ = api_client

    by_technique = client.get("/rules", params={"technique_id": "t1059.001"}).json()
    assert by_technique["count"] >= 1
    assert {r["technique_id"] for r in by_technique["rules"]} == {"T1059.001"}
    assert by_technique["total"] == len(get_loaded_rules())

    by_level = client.get("/rules", params={"level": "high"}).json()
    assert {r["level"] for r in by_level["rules"]} == {"high"}

    by_category = client.get("/rules", params={"category": "process_creation"}).json()
    assert {r["category"] for r in by_category["rules"]} == {"process_creation"}


def test_get_single_rule(api_client):
    client, _ = api_client

    response = client.get(f"/rules/{ENCODED_PS_RULE_ID}")

    assert response.status_code == 200
    assert response.json()["rule_id"] == ENCODED_PS_RULE_ID


def test_unknown_rule_id_is_404(api_client):
    client, _ = api_client

    response = client.get("/rules/not-a-real-rule")

    assert response.status_code == 404
    assert response.json()["detail"] == "rule not-a-real-rule not found"
