"""services/replay_service.py.

`emit_due_records` is driven directly with a fake `now` and the api_client
fixture's in-memory-SQLite sessionmaker -- no thread is ever started for
these. `_run_loop`/`start_replay`/`stop_replay` are covered with `spawn`
injected as a no-op, so the state-transition contract is checked without a
real background thread.
"""

import threading
from datetime import datetime, timedelta, timezone

import pytest

from app.detection.rule_loader import LoadedRule
from app.demo.timeline import ScheduledRecord
from app.models.alert import Alert
from app.models.incident import Incident
from app.services import replay_service
from app.services.replay_service import (
    ReplayAlreadyRunningError,
    ReplayRun,
    emit_due_records,
    get_current_run,
    start_replay,
    stop_replay,
)

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


def _record(system_time: str, command_line: str = "-enc AAA", computer: str = "Nightowl") -> dict:
    return {
        "Event": {
            "System": {"EventID": 1, "TimeCreated": {"@SystemTime": system_time}, "Computer": computer},
            "EventData": {"Data": [{"@Name": "CommandLine", "#text": command_line}]},
        }
    }


def _scheduled(record: dict, timestamp: datetime, emit_at: datetime, segment_id: str = "seg") -> ScheduledRecord:
    return ScheduledRecord(record=record, timestamp=timestamp, emit_at=emit_at, segment_id=segment_id)


def _new_run(records_total: int) -> ReplayRun:
    return ReplayRun(
        run_id="test-run",
        scenario_id="demo_shift",
        scenario_title="Test scenario",
        state="running",
        started_at=datetime.now(timezone.utc),
        duration_seconds=180,
        window_minutes=180,
        records_total=records_total,
    )


def test_emit_due_records_only_emits_records_due_by_now(api_client):
    _client, SessionLocal = api_client
    t0 = datetime(2026, 8, 28, 9, 0, 0, tzinfo=timezone.utc)
    schedule = [
        _scheduled(_record(t0.isoformat()), t0, t0),
        _scheduled(_record((t0 + timedelta(minutes=1)).isoformat()), t0 + timedelta(minutes=1), t0 + timedelta(seconds=60)),
    ]
    run = _new_run(records_total=2)

    with SessionLocal() as db:
        cursor = emit_due_records(db, run, schedule, cursor=0, now=t0 + timedelta(seconds=10), rules=[FAKE_RULE])

    assert cursor == 1
    assert run.records_emitted == 1
    assert run.alerts_created == 1


def test_emit_due_records_resumes_from_cursor_on_next_tick(api_client):
    _client, SessionLocal = api_client
    t0 = datetime(2026, 8, 28, 9, 0, 0, tzinfo=timezone.utc)
    schedule = [
        _scheduled(_record(t0.isoformat()), t0, t0),
        _scheduled(_record((t0 + timedelta(minutes=1)).isoformat()), t0 + timedelta(minutes=1), t0 + timedelta(seconds=60)),
    ]
    run = _new_run(records_total=2)

    with SessionLocal() as db:
        cursor = emit_due_records(db, run, schedule, cursor=0, now=t0, rules=[FAKE_RULE])
        assert cursor == 1
        cursor = emit_due_records(db, run, schedule, cursor=cursor, now=t0 + timedelta(seconds=90), rules=[FAKE_RULE])
        assert cursor == 2

    assert run.records_emitted == 2


def test_segments_80_minutes_apart_form_two_incidents(api_client):
    """The whole point of the replay: matched_at follows event time, so
    segments anchored far enough apart form separate incidents -- the
    grouping-window guarantee the manifest's anchors rely on."""
    _client, SessionLocal = api_client
    t0 = datetime(2026, 8, 28, 9, 0, 0, tzinfo=timezone.utc)
    later = t0 + timedelta(minutes=80)
    schedule = [
        _scheduled(_record(t0.isoformat()), t0, t0, segment_id="a"),
        _scheduled(_record(later.isoformat()), later, t0, segment_id="b"),
    ]
    run = _new_run(records_total=2)

    with SessionLocal() as db:
        emit_due_records(db, run, schedule, cursor=0, now=t0, rules=[FAKE_RULE])
        assert db.query(Incident).count() == 2
        assert len(run.incident_ids) == 2


def test_segments_3_minutes_apart_form_one_incident(api_client):
    _client, SessionLocal = api_client
    t0 = datetime(2026, 8, 28, 9, 0, 0, tzinfo=timezone.utc)
    later = t0 + timedelta(minutes=3)
    schedule = [
        _scheduled(_record(t0.isoformat()), t0, t0, segment_id="a"),
        _scheduled(_record(later.isoformat()), later, t0, segment_id="b"),
    ]
    run = _new_run(records_total=2)

    with SessionLocal() as db:
        emit_due_records(db, run, schedule, cursor=0, now=t0, rules=[FAKE_RULE])
        assert db.query(Incident).count() == 1
        assert len(run.incident_ids) == 1


def test_run_tracks_alert_and_event_counts_from_the_db(api_client):
    _client, SessionLocal = api_client
    t0 = datetime(2026, 8, 28, 9, 0, 0, tzinfo=timezone.utc)
    schedule = [_scheduled(_record(t0.isoformat()), t0, t0)]
    run = _new_run(records_total=1)

    with SessionLocal() as db:
        emit_due_records(db, run, schedule, cursor=0, now=t0, rules=[FAKE_RULE])
        assert run.events_ingested == db.query(Alert).count() == 1
        assert "Fake Encoded PowerShell Rule" in run.matched_rule_titles


def test_start_replay_rejects_a_second_concurrent_run(api_client):
    _client, SessionLocal = api_client
    start_replay("demo_shift", session_factory=SessionLocal, spawn=lambda target: None)

    with pytest.raises(ReplayAlreadyRunningError):
        start_replay("demo_shift", session_factory=SessionLocal, spawn=lambda target: None)


def test_start_replay_records_a_running_run(api_client):
    _client, SessionLocal = api_client
    run = start_replay("demo_shift", session_factory=SessionLocal, spawn=lambda target: None)

    assert run.state == "running"
    assert run.scenario_id == "demo_shift"
    assert run.records_total > 0
    assert get_current_run() is run


def test_stop_replay_sets_the_stop_event_for_the_running_run(api_client):
    _client, SessionLocal = api_client
    run = start_replay("demo_shift", session_factory=SessionLocal, spawn=lambda target: None)

    returned = stop_replay()

    assert returned is run
    assert replay_service._stop_event.is_set()


def test_stop_replay_when_nothing_is_running_returns_none():
    assert stop_replay() is None


def test_get_current_run_is_none_before_any_run():
    assert get_current_run() is None


def test_run_loop_finishes_when_schedule_exhausted(api_client, monkeypatch):
    """Drives the actual background-loop function, but with the tick
    shortened and a schedule that is entirely due immediately, so this
    takes milliseconds rather than the real demo's 3 minutes."""
    monkeypatch.setattr(replay_service.settings, "demo_replay_tick_seconds", 0.01)
    _client, SessionLocal = api_client
    t0 = datetime.now(timezone.utc)
    schedule = [_scheduled(_record(t0.isoformat()), t0, t0)]
    run = _new_run(records_total=1)
    stop_event = threading.Event()

    replay_service._run_loop(run, schedule, SessionLocal, stop_event)

    assert run.state == "finished"
    assert run.records_emitted == 1
    assert run.finished_at is not None


def test_run_loop_reports_stopped_when_stop_event_already_set(api_client):
    _client, SessionLocal = api_client
    t0 = datetime.now(timezone.utc)
    schedule = [_scheduled(_record(t0.isoformat()), t0, t0)]
    run = _new_run(records_total=1)
    stop_event = threading.Event()
    stop_event.set()

    replay_service._run_loop(run, schedule, SessionLocal, stop_event)

    assert run.state == "stopped"
    assert run.records_emitted == 0
    assert run.finished_at is not None


def test_run_loop_reports_failed_on_an_unexpected_exception(api_client, monkeypatch):
    _client, SessionLocal = api_client

    def _broken_emit(*args, **kwargs):
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(replay_service, "emit_due_records", _broken_emit)
    t0 = datetime.now(timezone.utc)
    schedule = [_scheduled(_record(t0.isoformat()), t0, t0)]
    run = _new_run(records_total=1)
    stop_event = threading.Event()

    replay_service._run_loop(run, schedule, SessionLocal, stop_event)

    assert run.state == "failed"
    assert "simulated failure" in run.error
