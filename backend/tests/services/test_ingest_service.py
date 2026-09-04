"""services/ingest_service.py -- the shared normalize -> persist -> detect
-> group pipeline extracted from routes_ingest.py, now with an
event-timestamped path (`matched_at=None`) used by the live-replay service.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.detection.rule_loader import LoadedRule
from app.models.alert import Alert
from app.models.incident import Incident
from app.services.ingest_service import ingest_records

FAKE_RULE = LoadedRule(
    rule_id="fake-rule-1",
    title="Fake Encoded PowerShell Rule",
    level="high",
    category="process_creation",
    detections={"selection": {"CommandLine|contains": "-enc"}},
    condition="selection",
    yaml_path="<test>",
    technique_id="T1059.001",
)


def _record(
    system_time: str, command_line: str | None = "-enc AAA", computer: str = "WORKSTATION01", channel: str | None = None
) -> dict:
    data = [] if command_line is None else [{"@Name": "CommandLine", "#text": command_line}]
    system = {"EventID": 1, "TimeCreated": {"@SystemTime": system_time}, "Computer": computer}
    if channel is not None:
        system["Channel"] = channel
    return {
        "Event": {
            "System": system,
            "EventData": {"Data": data},
        }
    }


def test_explicit_matched_at_stamps_every_alert_and_incident_the_same(api_client):
    _client, SessionLocal = api_client
    stamp = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
    records = [
        _record("2026-08-01T00:00:00+00:00"),  # deliberately old event timestamps --
        _record("2026-08-15T00:00:00+00:00"),  # explicit matched_at must win over these
    ]

    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[FAKE_RULE], matched_at=stamp)
        db.commit()

        assert outcome.alerts_created == 2
        assert len(outcome.incident_ids) == 1  # same stamp -> same 1h grouping window

        # SQLite (the in-memory test DB) strips tzinfo on round trip; the
        # values are still UTC, so compare naive-to-naive.
        alerts = db.query(Alert).all()
        assert all(alert.matched_at == stamp.replace(tzinfo=None) for alert in alerts)
        incident = db.query(Incident).one()
        assert incident.created_at == stamp.replace(tzinfo=None)


def test_matched_at_none_uses_each_event_own_timestamp(api_client):
    _client, SessionLocal = api_client
    early = datetime(2026, 8, 28, 9, 0, 0, tzinfo=timezone.utc)
    late = early + timedelta(hours=2)  # outside the 1h grouping window
    records = [_record(early.isoformat()), _record(late.isoformat())]

    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[FAKE_RULE], matched_at=None)
        db.commit()

        assert outcome.alerts_created == 2
        assert len(outcome.incident_ids) == 2  # far enough apart to form separate incidents

        alerts = {alert.matched_at for alert in db.query(Alert).all()}
        assert alerts == {early.replace(tzinfo=None), late.replace(tzinfo=None)}
        incidents = sorted(db.query(Incident).all(), key=lambda i: i.created_at)
        assert [i.created_at for i in incidents] == [early.replace(tzinfo=None), late.replace(tzinfo=None)]


def test_matched_at_none_within_the_grouping_window_joins_one_incident(api_client):
    _client, SessionLocal = api_client
    t0 = datetime(2026, 8, 28, 9, 0, 0, tzinfo=timezone.utc)
    records = [_record((t0 + timedelta(minutes=m)).isoformat()) for m in (0, 10, 20)]

    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[FAKE_RULE], matched_at=None)
        db.commit()
        assert len(outcome.incident_ids) == 1


def test_matched_at_none_requires_ascending_order(api_client):
    _client, SessionLocal = api_client
    t0 = datetime(2026, 8, 28, 9, 0, 0, tzinfo=timezone.utc)
    records = [_record(t0.isoformat()), _record((t0 - timedelta(minutes=5)).isoformat())]

    with SessionLocal() as db:
        with pytest.raises(ValueError, match="ascending"):
            ingest_records(db, records, rules=[FAKE_RULE], matched_at=None)


def test_non_matching_events_are_still_persisted_with_no_alerts(api_client):
    _client, SessionLocal = api_client
    records = [_record("2026-08-28T09:00:00+00:00", command_line="notepad.exe")]

    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[FAKE_RULE], matched_at=None)
        assert outcome.events_ingested == 1
        assert outcome.rule_matches == 0
        assert outcome.alerts_created == 0
        assert outcome.incident_ids == []


def test_malformed_record_is_skipped_and_counted(api_client):
    _client, SessionLocal = api_client
    malformed = {"Event": {"System": {"EventID": 1, "Computer": "H"}, "EventData": {"Data": []}}}  # no TimeCreated
    records = [_record("2026-08-28T09:00:00+00:00"), malformed]

    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[FAKE_RULE], matched_at=None)
        assert outcome.records_read == 2
        assert outcome.events_skipped == 1
        assert outcome.events_ingested == 1


# -- coverage honesty (covered_events / uncovered_events / breakdown) ------

_SYSMON_ONLY_RULE = LoadedRule(
    rule_id="fake-sysmon-rule",
    title="Fake Sysmon-Only Rule",
    level="high",
    category="process_creation",
    detections={"selection": {"CommandLine|contains": "-enc"}},
    condition="selection",
    yaml_path="<test>",
    technique_id="T1059.001",
    channel="sysmon",
)


def test_covered_and_uncovered_events_classified_across_two_channels_with_same_event_id(api_client):
    """The regression this fix exists for: an event_id shared by two
    channels (here, both records use event_id=1, one Sysmon-channel, one
    Security-channel) must be classified independently -- coverage from
    the Sysmon-scoped rule must not "leak" onto the Security event just
    because the numeric event_id matches."""
    _client, SessionLocal = api_client
    covered = _record("2026-08-28T09:00:00+00:00", channel="Microsoft-Windows-Sysmon/Operational")
    uncovered = _record("2026-08-28T09:00:01+00:00", channel="Security", command_line=None)
    records = [covered, uncovered]

    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[_SYSMON_ONLY_RULE], matched_at=None)

        assert outcome.covered_events == 1
        assert outcome.uncovered_events == 1
        assert len(outcome.uncovered_breakdown) == 1
        assert outcome.uncovered_breakdown[0].channel == "Security"
        assert outcome.uncovered_breakdown[0].event_id == 1
        assert outcome.uncovered_breakdown[0].count == 1


def test_uncovered_breakdown_groups_by_channel_and_event_id(api_client):
    _client, SessionLocal = api_client
    records = [
        _record(f"2026-08-28T09:00:0{i}+00:00", channel="Application", command_line=None) for i in range(3)
    ]

    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[_SYSMON_ONLY_RULE], matched_at=None)

        assert outcome.covered_events == 0
        assert outcome.uncovered_events == 3
        assert len(outcome.uncovered_breakdown) == 1  # all 3 grouped into one (channel, event_id) entry
        assert outcome.uncovered_breakdown[0].count == 3
