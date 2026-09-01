"""Day 9 verification (Pair 1): incident_service.py groups alerts into
incidents by same host + a 1-hour window. Uses an in-memory SQLite engine,
same pattern as services/test_event_service.py/services/test_detection_service.py.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.base import Base
from app.detection.engine import RuleMatch
from app.models.incident import Incident
from app.services import severity_service
from app.services.incident_service import count_incidents, find_or_create_incident, list_incidents

BASE_TIME = datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc)


def _engine():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine


def _match(rule_id="rule-1", title="Test Rule", level="high", technique_id="T1059.001"):
    # score is derived from level the same way the real engine derives it
    # (empty tactics -- these tests aren't exercising tactic weighting), so
    # every call site stays internally consistent without having to pass
    # a matching score by hand.
    return RuleMatch(rule_id=rule_id, title=title, level=level, score=severity_service.compute_severity_score(level, []), technique_id=technique_id)


def test_creates_new_incident_when_none_exists():
    with Session(_engine()) as db:
        incident = find_or_create_incident(db, "HOST-A", BASE_TIME, _match())
        db.commit()

        assert incident.id is not None
        assert incident.host == "HOST-A"
        assert incident.status == "open"
        assert incident.severity == "high"
        assert incident.mitre_technique_ids == ["T1059.001"]


def test_same_host_within_window_reuses_the_existing_incident():
    with Session(_engine()) as db:
        first = find_or_create_incident(db, "HOST-A", BASE_TIME, _match(technique_id="T1059.001"))
        db.commit()

        second = find_or_create_incident(
            db, "HOST-A", BASE_TIME + timedelta(minutes=30), _match(rule_id="rule-2", technique_id="T1105")
        )
        db.commit()

        assert second.id == first.id
        assert db.query(Incident).count() == 1
        assert set(second.mitre_technique_ids) == {"T1059.001", "T1105"}


def test_different_host_creates_a_separate_incident():
    with Session(_engine()) as db:
        first = find_or_create_incident(db, "HOST-A", BASE_TIME, _match())
        db.commit()

        second = find_or_create_incident(db, "HOST-B", BASE_TIME, _match())
        db.commit()

        assert second.id != first.id
        assert db.query(Incident).count() == 2


def test_outside_the_grouping_window_creates_a_separate_incident():
    with Session(_engine()) as db:
        first = find_or_create_incident(db, "HOST-A", BASE_TIME, _match())
        db.commit()

        second = find_or_create_incident(db, "HOST-A", BASE_TIME + timedelta(hours=2), _match())
        db.commit()

        assert second.id != first.id
        assert db.query(Incident).count() == 2


def test_merging_bumps_severity_to_the_higher_of_the_two():
    with Session(_engine()) as db:
        find_or_create_incident(db, "HOST-A", BASE_TIME, _match(level="low"))
        db.commit()

        merged = find_or_create_incident(
            db, "HOST-A", BASE_TIME + timedelta(minutes=10), _match(rule_id="rule-2", level="critical")
        )
        db.commit()

        assert merged.severity == "critical"
        assert merged.severity_score == 5


def test_merging_does_not_duplicate_an_already_present_technique_id():
    with Session(_engine()) as db:
        find_or_create_incident(db, "HOST-A", BASE_TIME, _match(technique_id="T1059.001"))
        db.commit()

        merged = find_or_create_incident(
            db, "HOST-A", BASE_TIME + timedelta(minutes=5), _match(rule_id="rule-2", technique_id="T1059.001")
        )
        db.commit()

        assert merged.mitre_technique_ids == ["T1059.001"]


def test_closed_incident_is_not_reused():
    with Session(_engine()) as db:
        first = find_or_create_incident(db, "HOST-A", BASE_TIME, _match())
        db.commit()
        first.status = "closed"
        db.commit()

        second = find_or_create_incident(db, "HOST-A", BASE_TIME + timedelta(minutes=10), _match())
        db.commit()

        assert second.id != first.id


def _seed_incidents(db, count: int):
    """Distinct hosts + widely spaced timestamps so none merge under the
    1-hour grouping window -- yields `count` separate incidents, oldest host
    ("HOST-0") created first / earliest timestamp."""
    incidents = []
    for i in range(count):
        incident = find_or_create_incident(db, f"HOST-{i}", BASE_TIME + timedelta(hours=i * 2), _match())
        incidents.append(incident)
    db.commit()
    return incidents


def test_list_incidents_limit_and_offset_page_through_distinct_results():
    with Session(_engine()) as db:
        _seed_incidents(db, 5)

        page1 = list_incidents(db, limit=2, offset=0)
        page2 = list_incidents(db, limit=2, offset=2)

        assert [i.id for i in page1] != [i.id for i in page2]
        assert len(page1) == 2
        assert len(page2) == 2
        # newest-first: HOST-4 (latest timestamp) leads page1
        assert page1[0].host == "HOST-4"
        assert page2[0].host == "HOST-2"


def test_list_incidents_without_limit_returns_everything():
    with Session(_engine()) as db:
        _seed_incidents(db, 5)

        assert len(list_incidents(db)) == 5


def test_count_incidents_matches_total_regardless_of_limit():
    with Session(_engine()) as db:
        _seed_incidents(db, 5)

        assert count_incidents(db) == 5
        assert len(list_incidents(db, limit=2)) == 2


def test_count_incidents_respects_the_same_filters_as_list_incidents():
    with Session(_engine()) as db:
        incidents = _seed_incidents(db, 3)
        incidents[0].severity = "critical"
        db.commit()

        assert count_incidents(db, severity="critical") == 1
        assert count_incidents(db, severity="no-such-severity") == 0
