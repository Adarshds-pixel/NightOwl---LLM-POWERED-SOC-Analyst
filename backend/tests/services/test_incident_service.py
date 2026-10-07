"""Day 9 verification (Pair 1): incident_service.py groups alerts into
incidents by same host + a 1-hour window. Uses an in-memory SQLite engine,
same pattern as services/test_event_service.py/services/test_detection_service.py.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.base import Base
from app.detection.engine import RuleMatch
from app.detection.rule_loader import get_loaded_rules
from app.detection.sequences import PROCESS_HERPADERPING
from app.models.event import Event
from app.models.incident import Incident
from app.services import severity_service
from app.services.detection_service import save_alerts
from app.services.incident_service import (
    build_incident_evidence,
    count_incidents,
    find_or_create_incident,
    get_related_events,
    list_incidents,
)

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


# -- get_related_events (evidence-first alerts, pending.md item 5) ---------


def _insert_event(db, **overrides) -> Event:
    fields = dict(
        host="HOST-A",
        timestamp=BASE_TIME,
        event_id=1,
        process="cmd.exe",
        command_line=None,
        user=None,
        raw_json={"raw": {}, "normalized": {}},
    )
    fields.update(overrides)
    event = Event(**fields)
    db.add(event)
    db.flush()
    return event


def test_get_related_events_finds_nearby_same_host_events():
    with Session(_engine()) as db:
        anchor = _insert_event(db, timestamp=BASE_TIME)
        nearby = _insert_event(db, timestamp=BASE_TIME + timedelta(minutes=2), command_line="whoami")
        db.commit()

        related = get_related_events(db, host="HOST-A", around=BASE_TIME, exclude_event_id=anchor.id)

        assert [e.id for e in related] == [nearby.id]


def test_get_related_events_excludes_the_anchor_event_itself():
    with Session(_engine()) as db:
        anchor = _insert_event(db, timestamp=BASE_TIME)
        db.commit()

        related = get_related_events(db, host="HOST-A", around=BASE_TIME, exclude_event_id=anchor.id)

        assert related == []


def test_get_related_events_excludes_events_outside_the_window():
    with Session(_engine()) as db:
        anchor = _insert_event(db, timestamp=BASE_TIME)
        _insert_event(db, timestamp=BASE_TIME + timedelta(minutes=30))  # well outside the 5-minute window
        db.commit()

        related = get_related_events(db, host="HOST-A", around=BASE_TIME, exclude_event_id=anchor.id)

        assert related == []


def test_get_related_events_excludes_events_on_a_different_host():
    with Session(_engine()) as db:
        anchor = _insert_event(db, host="HOST-A", timestamp=BASE_TIME)
        _insert_event(db, host="HOST-B", timestamp=BASE_TIME)
        db.commit()

        related = get_related_events(db, host="HOST-A", around=BASE_TIME, exclude_event_id=anchor.id)

        assert related == []


def test_get_related_events_capped_at_the_limit():
    with Session(_engine()) as db:
        anchor = _insert_event(db, timestamp=BASE_TIME)
        for i in range(8):
            _insert_event(db, timestamp=BASE_TIME + timedelta(seconds=i + 1))
        db.commit()

        related = get_related_events(db, host="HOST-A", around=BASE_TIME, exclude_event_id=anchor.id)

        assert len(related) == 5


# -- build_incident_evidence (AI/RAG evidence package, pending.md item 5) ---


def test_build_incident_evidence_with_no_alerts_returns_just_the_bare_fields():
    """An Incident row with no Alert pointing at it yet (shouldn't happen
    in practice -- find_or_create_incident always creates both together --
    but the function must not crash if it does)."""
    with Session(_engine()) as db:
        incident = Incident(
            title="Test incident", status="open", severity="high", severity_score=4,
            host="HOST-A", created_at=BASE_TIME, mitre_technique_ids=["T1059.001"],
        )
        db.add(incident)
        db.commit()

        evidence = build_incident_evidence(db, incident)

        assert evidence == {
            "description": "Test incident",
            "severity": "high",
            "host": "HOST-A",
            "technique_id": "T1059.001",
            "technique_ids": ["T1059.001"],
        }


def test_build_incident_evidence_includes_process_and_rule_from_the_first_alert():
    # matched_rule is resolved from the real loaded rule set by rule_id
    # (same as get_incident_detail's own rules_by_id lookup), not from
    # whatever title happens to be on the stored RuleMatch/Alert -- so
    # this needs a real loaded rule's id, not a synthetic "rule-1".
    real_rule = get_loaded_rules()[0]
    with Session(_engine()) as db:
        event = _insert_event(
            db, process="powershell.exe", command_line="powershell.exe -enc SQBFAFgA...", user="jdoe"
        )
        match = _match(rule_id=real_rule.rule_id, title=real_rule.title)
        incident = find_or_create_incident(db, "HOST-A", BASE_TIME, match)
        db.commit()
        save_alerts(db, [(event.id, match, BASE_TIME, incident.id)])

        evidence = build_incident_evidence(db, incident)

        assert evidence["matched_rule"] == real_rule.title
        assert evidence["detection_method"] == "single-event Sigma rule"
        assert evidence["process"] == "powershell.exe"
        assert evidence["command_line"] == "powershell.exe -enc SQBFAFgA..."
        assert evidence["user"] == "jdoe"
        assert "additional_alerts" not in evidence


def test_build_incident_evidence_includes_parent_process():
    with Session(_engine()) as db:
        event = _insert_event(db, parent_process="explorer.exe")
        incident = find_or_create_incident(db, "HOST-A", BASE_TIME, _match())
        db.commit()
        save_alerts(db, [(event.id, _match(), BASE_TIME, incident.id)])

        evidence = build_incident_evidence(db, incident)

        assert evidence["parent_process"] == "explorer.exe"


def test_build_incident_evidence_labels_a_sequence_match_as_sequence_correlation():
    """A sequence-detected alert's rule_id (detection/sequences.py) is
    never a loaded YAML rule -- this must resolve its title/method via
    SEQUENCE_PATTERNS, the same merge get_incident_detail's own
    rules_by_id already relies on, not silently show 'None'."""
    with Session(_engine()) as db:
        event = _insert_event(db)
        sequence_match = RuleMatch(
            rule_id=PROCESS_HERPADERPING.rule_id,
            title=PROCESS_HERPADERPING.title,
            level=PROCESS_HERPADERPING.level,
            score=severity_service.compute_severity_score(PROCESS_HERPADERPING.level, PROCESS_HERPADERPING.tactics),
            technique_id=PROCESS_HERPADERPING.technique_id,
        )
        incident = find_or_create_incident(db, "HOST-A", BASE_TIME, sequence_match)
        db.commit()
        save_alerts(db, [(event.id, sequence_match, BASE_TIME, incident.id)])

        evidence = build_incident_evidence(db, incident)

        assert evidence["matched_rule"] == PROCESS_HERPADERPING.title
        assert evidence["detection_method"] == "multi-event sequence correlation"


def test_build_incident_evidence_includes_nearby_related_events():
    with Session(_engine()) as db:
        anchor = _insert_event(db, timestamp=BASE_TIME)
        _insert_event(db, timestamp=BASE_TIME + timedelta(minutes=1), command_line="whoami")
        incident = find_or_create_incident(db, "HOST-A", BASE_TIME, _match())
        db.commit()
        save_alerts(db, [(anchor.id, _match(), BASE_TIME, incident.id)])

        evidence = build_incident_evidence(db, incident)

        assert len(evidence["related_events"]) == 1
        assert "whoami" in evidence["related_events"][0]


def test_build_incident_evidence_omits_related_events_key_when_none_nearby():
    with Session(_engine()) as db:
        event = _insert_event(db)
        incident = find_or_create_incident(db, "HOST-A", BASE_TIME, _match())
        db.commit()
        save_alerts(db, [(event.id, _match(), BASE_TIME, incident.id)])

        evidence = build_incident_evidence(db, incident)

        assert "related_events" not in evidence


def test_build_incident_evidence_counts_additional_alerts_instead_of_detailing_them():
    """An incident with many near-duplicate alerts from the same rule
    (e.g. Remote Thread Creation firing once per matching event in a
    file) must not balloon the prompt with every one of them -- only the
    first alert is detailed, the rest are counted."""
    with Session(_engine()) as db:
        first_event = _insert_event(db, timestamp=BASE_TIME)
        second_event = _insert_event(db, event_id=2, timestamp=BASE_TIME + timedelta(minutes=10))
        incident = find_or_create_incident(db, "HOST-A", BASE_TIME, _match(rule_id="rule-1"))
        db.commit()
        save_alerts(
            db,
            [
                (first_event.id, _match(rule_id="rule-1"), BASE_TIME, incident.id),
                (second_event.id, _match(rule_id="rule-1"), BASE_TIME + timedelta(minutes=10), incident.id),
            ],
        )

        evidence = build_incident_evidence(db, incident)

        assert evidence["additional_alerts"] == "1 more rule alert(s) matched on this incident, not individually listed here"
