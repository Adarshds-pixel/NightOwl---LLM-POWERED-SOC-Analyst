"""Day 8 verification (Pair 1): detection_service.py persists rule matches
as Alert rows. Uses an in-memory SQLite engine, same pattern as
services/test_event_service.py, so this runs offline without a live Postgres.
"""

from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.base import Base
from app.detection.engine import RuleMatch
from app.models.alert import Alert
from app.schemas.event import NormalizedEvent
from app.services.detection_service import create_alert, save_alerts
from app.services.event_service import create_event

MATCHED_AT = datetime(2026, 8, 18, 12, 0, 0, tzinfo=timezone.utc)


def _engine():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine


def _persisted_event(db):
    normalized = NormalizedEvent(
        host="WORKSTATION01",
        timestamp=datetime(2026, 8, 18, tzinfo=timezone.utc),
        event_id=1,
        process=r"C:\Windows\System32\certutil.exe",
        raw={},
    )
    event = create_event(db, normalized)
    db.commit()
    db.refresh(event)
    return event


def test_create_alert_persists_fk_severity_and_matched_at():
    with Session(_engine()) as db:
        event = _persisted_event(db)
        match = RuleMatch(rule_id="rule-1", title="Test Rule", level="high")

        alert = create_alert(db, event.id, match, MATCHED_AT)
        db.commit()
        db.refresh(alert)

        assert alert.id is not None
        assert alert.event_id == event.id
        assert alert.rule_id == "rule-1"
        assert alert.severity == "high"
        # SQLite (unlike Postgres) doesn't preserve tzinfo across a round
        # trip, so compare naively -- this is a SQLite-test-only quirk,
        # not something the app needs to handle for real Postgres usage.
        assert alert.matched_at.replace(tzinfo=timezone.utc) == MATCHED_AT


def test_save_alerts_commits_and_returns_rows_with_ids():
    with Session(_engine()) as db:
        event = _persisted_event(db)
        match_1 = RuleMatch(rule_id="rule-1", title="Test Rule 1", level="high")
        match_2 = RuleMatch(rule_id="rule-2", title="Test Rule 2", level="medium")

        rows = save_alerts(
            db,
            [(event.id, match_1, MATCHED_AT, None), (event.id, match_2, MATCHED_AT, None)],
        )

        assert len(rows) == 2
        assert all(row.id is not None for row in rows)
        assert db.query(Alert).count() == 2


def test_save_alerts_empty_list_is_a_noop():
    with Session(_engine()) as db:
        rows = save_alerts(db, [])
        assert rows == []
        assert db.query(Alert).count() == 0


def test_save_alerts_logs_persisted_count(caplog):
    with Session(_engine()) as db:
        event = _persisted_event(db)
        match = RuleMatch(rule_id="rule-1", title="Test Rule", level="high")
        with caplog.at_level("INFO"):
            save_alerts(db, [(event.id, match, MATCHED_AT, None)])
        assert "persisted 1 alerts" in caplog.text


def test_persisted_alert_roundtrips_from_db():
    engine = _engine()
    with Session(engine) as db:
        event = _persisted_event(db)
        match = RuleMatch(rule_id="rule-1", title="Test Rule", level="critical")
        alert = create_alert(db, event.id, match, MATCHED_AT)
        db.commit()
        alert_id = alert.id

    with Session(engine) as db:
        fetched = db.get(Alert, alert_id)
        assert fetched is not None
        assert fetched.severity == "critical"
        assert fetched.rule_id == "rule-1"
