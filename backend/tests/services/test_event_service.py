"""Day 5 verification (Pair 1): event_service.py persists NormalizedEvent
rows via the Event model. Uses an in-memory SQLite engine, same pattern as
test_health_and_models.py, so this runs offline without a live Postgres.

list_events/count_events/get_alerts_for_event_ids (GET /events, the raw
event-timeline endpoint) verified further below, same in-memory-SQLite
pattern as tests/services/test_incident_service.py.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.base import Base
from app.models.alert import Alert
from app.models.event import Event
from app.schemas.event import NormalizedEvent
from app.services.event_service import (
    count_events,
    create_event,
    get_alerts_for_event_ids,
    list_events,
    save_events,
)


def _engine():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine


def _normalized_event(**overrides):
    fields = dict(
        host="WORKSTATION01",
        timestamp=datetime(2026, 5, 24, 15, 25, 16, tzinfo=timezone.utc),
        event_id=1,
        process=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c whoami",
        user=r"WORKSTATION01\alice",
        raw={"Event": {"System": {"EventID": "1"}}},
    )
    fields.update(overrides)
    return NormalizedEvent(**fields)


def test_create_event_persists_flat_columns_from_normalized():
    with Session(_engine()) as db:
        normalized = _normalized_event()
        event = create_event(db, normalized)
        db.commit()
        db.refresh(event)

        assert event.id is not None
        assert event.host == "WORKSTATION01"
        assert event.event_id == 1
        assert event.process == r"C:\Windows\System32\cmd.exe"
        assert event.command_line == "cmd.exe /c whoami"
        assert event.user == r"WORKSTATION01\alice"


def test_create_event_raw_json_contains_raw_and_normalized_keys():
    with Session(_engine()) as db:
        normalized = _normalized_event()
        event = create_event(db, normalized)
        db.commit()
        db.refresh(event)

        assert set(event.raw_json.keys()) == {"raw", "normalized"}
        assert event.raw_json["raw"] == normalized.raw


def test_raw_json_normalized_section_excludes_raw_key():
    with Session(_engine()) as db:
        normalized = _normalized_event()
        event = create_event(db, normalized)
        db.commit()
        db.refresh(event)

        assert "raw" not in event.raw_json["normalized"]


def test_save_events_commits_and_returns_rows_with_ids():
    with Session(_engine()) as db:
        events = [
            _normalized_event(),
            _normalized_event(event_id=3, process="svchost.exe", command_line=None),
        ]
        rows = save_events(db, events)

        assert len(rows) == 2
        assert all(row.id is not None for row in rows)
        assert db.query(Event).count() == 2


def test_save_events_empty_list_is_a_noop():
    with Session(_engine()) as db:
        rows = save_events(db, [])
        assert rows == []
        assert db.query(Event).count() == 0


def test_save_events_logs_ingested_count(caplog):
    with Session(_engine()) as db:
        with caplog.at_level("INFO"):
            save_events(db, [_normalized_event()])
        assert "ingested 1 events" in caplog.text


def test_persisted_event_roundtrips_from_db():
    engine = _engine()
    with Session(engine) as db:
        normalized = _normalized_event(
            event_id=3,
            process="svchost.exe",
            command_line=None,
            destination_ip="8.8.8.8",
            destination_port=443,
        )
        event = create_event(db, normalized)
        db.commit()
        event_id = event.id

    with Session(engine) as db:
        fetched = db.get(Event, event_id)
        assert fetched is not None
        assert fetched.raw_json["normalized"]["destination_ip"] == "8.8.8.8"
        assert fetched.raw_json["normalized"]["destination_port"] == 443


BASE_TIME = datetime(2026, 8, 25, 12, 0, 0, tzinfo=timezone.utc)


def _insert_event(db, **overrides) -> Event:
    fields = dict(host="HOST-A", timestamp=BASE_TIME, event_id=1, process="cmd.exe", command_line=None, user=None)
    fields.update(overrides)
    event = Event(raw_json={"raw": {}, "normalized": {}}, **fields)
    db.add(event)
    db.flush()
    return event


def _insert_alert(db, event_id: int, **overrides) -> Alert:
    fields = dict(rule_id="rule-1", matched_at=BASE_TIME, severity="high")
    fields.update(overrides)
    alert = Alert(event_id=event_id, **fields)
    db.add(alert)
    db.flush()
    return alert


def test_list_events_defaults_to_newest_first():
    with Session(_engine()) as db:
        older = _insert_event(db, timestamp=BASE_TIME)
        newer = _insert_event(db, timestamp=BASE_TIME + timedelta(minutes=5))
        db.commit()

        events = list_events(db)

        assert [e.id for e in events] == [newer.id, older.id]


def test_list_events_filters_by_host():
    with Session(_engine()) as db:
        _insert_event(db, host="HOST-A")
        target = _insert_event(db, host="HOST-B")
        db.commit()

        events = list_events(db, host="HOST-B")

        assert [e.id for e in events] == [target.id]


def test_list_events_alert_only_true_restricts_to_alerted_events():
    with Session(_engine()) as db:
        alerted = _insert_event(db)
        _insert_event(db)  # no alert
        _insert_alert(db, alerted.id)
        db.commit()

        events = list_events(db, alert_only=True)

        assert [e.id for e in events] == [alerted.id]


def test_list_events_alert_only_false_restricts_to_normal_events():
    with Session(_engine()) as db:
        alerted = _insert_event(db)
        normal = _insert_event(db)
        _insert_alert(db, alerted.id)
        db.commit()

        events = list_events(db, alert_only=False)

        assert [e.id for e in events] == [normal.id]


def test_list_events_severity_restricts_to_events_with_an_alert_of_that_severity():
    with Session(_engine()) as db:
        critical_event = _insert_event(db)
        high_event = _insert_event(db)
        _insert_event(db)  # no alert at all
        _insert_alert(db, critical_event.id, rule_id="rule-critical", severity="critical")
        _insert_alert(db, high_event.id, rule_id="rule-high", severity="high")
        db.commit()

        assert [e.id for e in list_events(db, severity="critical")] == [critical_event.id]
        assert [e.id for e in list_events(db, severity="high")] == [high_event.id]
        assert list_events(db, severity="low") == []


def test_count_events_severity_matches_the_filtered_list_not_the_whole_table():
    """The bug this guards: the frontend used to narrow severity client-side
    over one fetched page, so a filtered view's row count disagreed with its
    own pagination total. count_events must apply the same filter."""
    with Session(_engine()) as db:
        critical_event = _insert_event(db)
        for _ in range(4):
            _insert_event(db)  # noise, no alerts
        _insert_alert(db, critical_event.id, rule_id="rule-critical", severity="critical")
        db.commit()

        assert count_events(db) == 5
        assert count_events(db, severity="critical") == 1
        assert count_events(db, severity="critical") == len(list_events(db, severity="critical"))


def test_list_events_severity_counts_an_event_once_even_if_two_rules_of_that_severity_matched():
    """An event that trips two critical rules is still one event in this
    event-level view -- the EXISTS filter must not fan it out into two rows."""
    with Session(_engine()) as db:
        event = _insert_event(db)
        _insert_alert(db, event.id, rule_id="rule-a", severity="critical")
        _insert_alert(db, event.id, rule_id="rule-b", severity="critical")
        db.commit()

        assert [e.id for e in list_events(db, severity="critical")] == [event.id]
        assert count_events(db, severity="critical") == 1


def test_list_events_limit_and_offset_page_through_distinct_results():
    with Session(_engine()) as db:
        for i in range(5):
            _insert_event(db, timestamp=BASE_TIME + timedelta(minutes=i))
        db.commit()

        page1 = list_events(db, limit=2, offset=0)
        page2 = list_events(db, limit=2, offset=2)

        assert len(page1) == 2
        assert len(page2) == 2
        assert {e.id for e in page1}.isdisjoint({e.id for e in page2})


def test_count_events_ignores_limit_reflects_full_filtered_total():
    with Session(_engine()) as db:
        for i in range(5):
            _insert_event(db, timestamp=BASE_TIME + timedelta(minutes=i))
        db.commit()

        assert count_events(db) == 5
        assert len(list_events(db, limit=2)) == 2


def test_get_alerts_for_event_ids_empty_list_returns_empty_dict():
    with Session(_engine()) as db:
        assert get_alerts_for_event_ids(db, []) == {}


def test_get_alerts_for_event_ids_picks_highest_severity_when_event_matched_multiple_rules():
    with Session(_engine()) as db:
        event = _insert_event(db)
        _insert_alert(db, event.id, rule_id="rule-low", severity="low")
        _insert_alert(db, event.id, rule_id="rule-critical", severity="critical")
        db.commit()

        result = get_alerts_for_event_ids(db, [event.id])

        assert result[event.id].severity == "critical"
        assert result[event.id].rule_id == "rule-critical"


def test_get_alerts_for_event_ids_omits_events_with_no_alert():
    with Session(_engine()) as db:
        event = _insert_event(db)
        db.commit()

        result = get_alerts_for_event_ids(db, [event.id])

        assert result == {}
