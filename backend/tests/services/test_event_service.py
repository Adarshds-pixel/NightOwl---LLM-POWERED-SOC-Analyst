"""Day 5 verification (Pair 1): event_service.py persists NormalizedEvent
rows via the Event model. Uses an in-memory SQLite engine, same pattern as
test_health_and_models.py, so this runs offline without a live Postgres.
"""

from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.base import Base
from app.models.event import Event
from app.schemas.event import NormalizedEvent
from app.services.event_service import create_event, save_events


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
