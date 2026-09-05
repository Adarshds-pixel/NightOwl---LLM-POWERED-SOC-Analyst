"""services/ingest_service.py -- the shared normalize -> persist -> detect
-> group pipeline extracted from routes_ingest.py, now with an
event-timestamped path (`matched_at=None`) used by the live-replay service.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.detection.rule_loader import LoadedRule
from app.models.alert import Alert
from app.models.event import Event
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
    system_time: str,
    command_line: str | None = "-enc AAA",
    computer: str = "WORKSTATION01",
    channel: str | None = None,
    provider: str | None = None,
    event_record_id: int | None = None,
) -> dict:
    data = [] if command_line is None else [{"@Name": "CommandLine", "#text": command_line}]
    system = {"EventID": 1, "TimeCreated": {"@SystemTime": system_time}, "Computer": computer}
    if channel is not None:
        system["Channel"] = channel
    if provider is not None:
        system["Provider"] = {"@Name": provider}
    if event_record_id is not None:
        system["EventRecordID"] = str(event_record_id)
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


# -- telemetry profiler (channels / providers / event_id_breakdown) --------


def test_event_id_breakdown_includes_covered_and_uncovered_groups(api_client):
    """event_id_breakdown is a superset of uncovered_breakdown -- it must
    include the covered group too, with covered=True, not just the
    uncovered one uncovered_breakdown already reports."""
    _client, SessionLocal = api_client
    covered = _record("2026-08-28T09:00:00+00:00", channel="Microsoft-Windows-Sysmon/Operational")
    uncovered = _record("2026-08-28T09:00:01+00:00", channel="Security", command_line=None)
    records = [covered, uncovered]

    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[_SYSMON_ONLY_RULE], matched_at=None)

        assert len(outcome.event_id_breakdown) == 2
        by_channel = {g.channel: g for g in outcome.event_id_breakdown}
        assert by_channel["Microsoft-Windows-Sysmon/Operational"].covered is True
        assert by_channel["Microsoft-Windows-Sysmon/Operational"].event_id == 1
        assert by_channel["Security"].covered is False
        assert by_channel["Security"].event_id == 1


def test_event_id_breakdown_sorted_by_count_descending(api_client):
    _client, SessionLocal = api_client
    records = [
        _record("2026-08-28T09:00:00+00:00", channel="Security", command_line=None),
        _record("2026-08-28T09:00:01+00:00", channel="Microsoft-Windows-Sysmon/Operational"),
        _record("2026-08-28T09:00:02+00:00", channel="Microsoft-Windows-Sysmon/Operational"),
    ]

    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[_SYSMON_ONLY_RULE], matched_at=None)

        assert [g.count for g in outcome.event_id_breakdown] == [2, 1]
        assert outcome.event_id_breakdown[0].channel == "Microsoft-Windows-Sysmon/Operational"


def test_channels_and_providers_are_distinct_and_sorted(api_client):
    _client, SessionLocal = api_client
    records = [
        _record("2026-08-28T09:00:00+00:00", channel="Security", provider="Microsoft-Windows-Security-Auditing"),
        _record("2026-08-28T09:00:01+00:00", channel="Microsoft-Windows-Sysmon/Operational", provider="Microsoft-Windows-Sysmon"),
        # A second Sysmon-channel/provider record: must not duplicate the entry.
        _record("2026-08-28T09:00:02+00:00", channel="Microsoft-Windows-Sysmon/Operational", provider="Microsoft-Windows-Sysmon"),
    ]

    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[_SYSMON_ONLY_RULE], matched_at=None)

        assert outcome.channels == ["Microsoft-Windows-Sysmon/Operational", "Security"]
        assert outcome.providers == ["Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Sysmon"]


def test_channels_and_providers_empty_when_absent_from_the_record(api_client):
    """A record with no Channel/Provider in its System block (both optional
    per normalizer.py) must not crash or fabricate a value."""
    _client, SessionLocal = api_client
    records = [_record("2026-08-28T09:00:00+00:00", channel=None, provider=None)]

    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[FAKE_RULE], matched_at=None)

        assert outcome.channels == []
        assert outcome.providers == []


# -- advisory patterns (named_pipe_discovery_event_ids) --------------------

# pipe_event (event ids 17/18) IS a covered category (rogue_spoolss_named_
# pipe.yml), so this is deliberately NOT the coverage-gap path above -- it
# exercises the separate, independent advisory-pattern signal.
_PIPE_CONNECT_RULE = LoadedRule(
    rule_id="fake-spoolss-rule",
    title="Fake Spoolss Pipe Rule",
    level="high",
    category="pipe_event",
    detections={"selection": {"PipeName|endswith": "spoolss"}},
    condition="selection",
    yaml_path="<test>",
    technique_id="T1055",
    channel="sysmon",
)


def _pipe_record(system_time, pipe_name, image="System", channel="Microsoft-Windows-Sysmon/Operational"):
    return {
        "Event": {
            "System": {
                "EventID": 18,
                "TimeCreated": {"@SystemTime": system_time},
                "Computer": "WORKSTATION01",
                "Channel": channel,
            },
            "EventData": {
                "Data": [
                    {"@Name": "Image", "#text": image},
                    {"@Name": "PipeName", "#text": pipe_name},
                ]
            },
        }
    }


def test_named_pipe_discovery_flagged_even_when_event_id_is_covered_and_no_rule_matches(api_client):
    """\\lsass over SMB from System: event_id 18 IS covered (pipe_event has
    a loaded rule), and no rule matches (the loaded rule targets spoolss
    only) -- this must still surface via the advisory-pattern list, not
    silently read as "fully covered and clean"."""
    _client, SessionLocal = api_client
    records = [_pipe_record("2026-08-28T09:00:00+00:00", "\\lsass")]

    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[_PIPE_CONNECT_RULE], matched_at=None)

        assert outcome.rule_matches == 0
        assert outcome.covered_events == 1
        assert outcome.uncovered_events == 0
        assert len(outcome.named_pipe_discovery_event_ids) == 1


def test_named_pipe_discovery_flagged_alongside_a_real_rule_match_elsewhere_in_the_file(api_client):
    """The pipe connect and an unrelated real detection can both be true
    for the same file -- the advisory flag must not require rule_matches
    to be zero, unlike the uncovered-events trigger."""
    _client, SessionLocal = api_client
    records = [
        _record("2026-08-28T09:00:00+00:00", command_line="-enc AAA"),  # matches FAKE_RULE
        _pipe_record("2026-08-28T09:00:01+00:00", "\\srvsvc"),
    ]

    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[FAKE_RULE, _PIPE_CONNECT_RULE], matched_at=None)

        assert outcome.rule_matches == 1
        assert len(outcome.named_pipe_discovery_event_ids) == 1


def test_named_pipe_discovery_does_not_flag_unrelated_pipes_or_processes(api_client):
    """A benign look-alike: same event_id/channel, but neither the pipe
    name nor the process is the sensitive combination -- e.g. mmc.exe
    connecting to \\wkssvc (real content also seen in the verified
    fixture, alongside the genuine \\lsass/\\srvsvc connects)."""
    _client, SessionLocal = api_client
    records = [
        _pipe_record("2026-08-28T09:00:00+00:00", "\\wkssvc", image="C:\\Windows\\system32\\mmc.exe"),
        _pipe_record("2026-08-28T09:00:01+00:00", "\\browser", image="System"),
    ]

    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[_PIPE_CONNECT_RULE], matched_at=None)

        assert outcome.named_pipe_discovery_event_ids == []


# -- duplicate-ingest detection ---------------------------------------------
# The reported bug: re-uploading the same EVTX file (or one that overlaps an
# earlier upload) must not double events_ingested, alerts_created, or
# incident_ids -- every KPI derived from those on every page.


def test_reingesting_the_same_records_creates_no_new_events(api_client):
    _client, SessionLocal = api_client
    records = [
        _record("2026-08-28T09:00:00+00:00", event_record_id=101),
        _record("2026-08-28T09:00:01+00:00", event_record_id=102),
    ]

    with SessionLocal() as db:
        first = ingest_records(db, records, rules=[FAKE_RULE], matched_at=None)
        assert first.events_ingested == 2
        assert first.duplicate_events_skipped == 0

        second = ingest_records(db, records, rules=[FAKE_RULE], matched_at=None)

        assert second.events_ingested == 0
        assert second.duplicate_events_skipped == 2
        assert db.query(Event).count() == 2


def test_reingesting_the_same_records_creates_no_new_alerts_or_incidents(api_client):
    """The exact symptom reported: incidents looked deduplicated only
    because find_or_create_incident() merges same-host alerts within its
    grouping window -- the underlying Alert/Event rows, and every count
    derived from them, still doubled underneath it. A duplicate event must
    never even reach rule evaluation, so alerts_created/incident_ids on the
    repeat ingest are genuinely zero/empty, not merged-and-hidden."""
    _client, SessionLocal = api_client
    records = [_record("2026-08-28T09:00:00+00:00", event_record_id=101)]  # matches FAKE_RULE

    with SessionLocal() as db:
        first = ingest_records(db, records, rules=[FAKE_RULE], matched_at=None)
        assert first.alerts_created == 1
        first_incident_id = first.incident_ids[0]

        second = ingest_records(db, records, rules=[FAKE_RULE], matched_at=None)

        assert second.alerts_created == 0
        assert second.incident_ids == []
        assert db.query(Alert).count() == 1
        assert db.query(Incident).count() == 1
        assert db.query(Incident).one().id == first_incident_id


def test_partial_overlap_only_the_new_records_are_ingested(api_client):
    """A re-export that overlaps an earlier upload (real EVTX workflow,
    not just an exact re-upload) -- only the genuinely new record must be
    stored."""
    _client, SessionLocal = api_client
    already_seen = _record("2026-08-28T09:00:00+00:00", event_record_id=101)
    new_record = _record("2026-08-28T09:00:01+00:00", event_record_id=102)

    with SessionLocal() as db:
        ingest_records(db, [already_seen], rules=[FAKE_RULE], matched_at=None)

        outcome = ingest_records(db, [already_seen, new_record], rules=[FAKE_RULE], matched_at=None)

        assert outcome.events_ingested == 1
        assert outcome.duplicate_events_skipped == 1
        assert db.query(Event).count() == 2


def test_events_without_an_event_record_id_are_never_deduplicated(api_client):
    """A record genuinely missing EventRecordID (malformed/legacy) can
    never be proven a duplicate -- it must not be silently dropped just
    because an earlier ingest also lacked one."""
    _client, SessionLocal = api_client
    records = [_record("2026-08-28T09:00:00+00:00", event_record_id=None)]

    with SessionLocal() as db:
        first = ingest_records(db, records, rules=[FAKE_RULE], matched_at=None)
        second = ingest_records(db, records, rules=[FAKE_RULE], matched_at=None)

        assert first.events_ingested == 1
        assert second.events_ingested == 1
        assert second.duplicate_events_skipped == 0
        assert db.query(Event).count() == 2


def test_same_event_record_id_on_different_hosts_is_not_a_duplicate(api_client):
    """EventRecordID is only unique per (host, channel) log, not globally
    -- two different real machines can each have a record 101."""
    _client, SessionLocal = api_client
    records = [
        _record("2026-08-28T09:00:00+00:00", computer="HOST-A", event_record_id=101),
        _record("2026-08-28T09:00:01+00:00", computer="HOST-B", event_record_id=101),
    ]

    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[FAKE_RULE], matched_at=None)

        assert outcome.events_ingested == 2
        assert outcome.duplicate_events_skipped == 0


def test_same_event_record_id_on_different_channels_is_not_a_duplicate(api_client):
    _client, SessionLocal = api_client
    records = [
        _record("2026-08-28T09:00:00+00:00", channel="Microsoft-Windows-Sysmon/Operational", event_record_id=101),
        _record("2026-08-28T09:00:01+00:00", channel="Security", event_record_id=101),
    ]

    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[FAKE_RULE], matched_at=None)

        assert outcome.events_ingested == 2
        assert outcome.duplicate_events_skipped == 0


def test_duplicate_records_within_the_same_batch_are_deduplicated_too(api_client):
    """Not just against previously-persisted rows -- the exact same record
    appearing twice in one upload (e.g. a malformed export) must not
    create two Event rows either."""
    _client, SessionLocal = api_client
    records = [
        _record("2026-08-28T09:00:00+00:00", event_record_id=101),
        _record("2026-08-28T09:00:01+00:00", event_record_id=101),
    ]

    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[FAKE_RULE], matched_at=None)

        assert outcome.events_ingested == 1
        assert outcome.duplicate_events_skipped == 1
