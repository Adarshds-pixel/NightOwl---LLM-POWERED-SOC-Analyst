"""Pure rebasing math -- no DB, no clock, no scenario files. See
app/demo/timeline.py's module docstring for the two-mapping design this
exercises: capture time -> simulated time -> wall-clock emit time.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.demo.timeline import (
    ScheduledRecord,
    SegmentInput,
    build_schedule,
    rebase_segment,
    record_timestamp,
    resolve_time_scale,
    simulated_to_wall_clock,
    with_rebased_timestamp,
)


def _record(system_time: str, extra: dict | None = None) -> dict:
    event = {
        "System": {"EventID": 1, "Computer": "Nightowl", "TimeCreated": {"@SystemTime": system_time}},
        "EventData": {"Data": [{"@Name": "Image", "#text": "powershell.exe"}]},
    }
    if extra:
        event.update(extra)
    return {"Event": event}


BASE = datetime(2026, 8, 16, 12, 0, 0, tzinfo=timezone.utc)


def test_with_rebased_timestamp_changes_only_time_created():
    record = _record("2026-08-16T12:00:00+00:00")
    new_time = datetime(2026, 8, 27, 9, 30, 0, tzinfo=timezone.utc)

    rebased = with_rebased_timestamp(record, new_time)

    assert rebased["Event"]["System"]["TimeCreated"]["@SystemTime"] == new_time.isoformat()
    # Every other field, deep-compared, is untouched.
    rebased_without_time = dict(rebased["Event"]["System"])
    del rebased_without_time["TimeCreated"]
    original_without_time = dict(record["Event"]["System"])
    del original_without_time["TimeCreated"]
    assert rebased_without_time == original_without_time
    assert rebased["Event"]["EventData"] == record["Event"]["EventData"]


def test_with_rebased_timestamp_does_not_mutate_the_input():
    record = _record("2026-08-16T12:00:00+00:00")
    with_rebased_timestamp(record, BASE + timedelta(hours=1))
    assert record["Event"]["System"]["TimeCreated"]["@SystemTime"] == "2026-08-16T12:00:00+00:00"


def test_record_timestamp_matches_normalizer_parsing():
    record = _record("2026-08-16T12:00:00Z")
    assert record_timestamp(record) == datetime(2026, 8, 16, 12, 0, 0, tzinfo=timezone.utc)


def test_rebase_segment_preserves_order_and_proportional_spacing():
    records = [_record((BASE + timedelta(seconds=s)).isoformat()) for s in (0, 5, 29)]
    anchor = datetime(2026, 8, 27, 10, 0, 0, tzinfo=timezone.utc)

    rebased = rebase_segment(records, record_timestamp, anchor, time_scale=2.0)

    timestamps = [ts for _, ts in rebased]
    assert timestamps[0] == anchor
    assert timestamps[1] == anchor + timedelta(seconds=10)  # 5s * scale 2
    assert timestamps[2] == anchor + timedelta(seconds=58)  # 29s * scale 2
    assert timestamps == sorted(timestamps)


def test_rebase_segment_empty_input():
    assert rebase_segment([], record_timestamp, BASE, 1.0) == []


def test_resolve_time_scale_fills_target_span():
    records = [_record((BASE + timedelta(minutes=m)).isoformat()) for m in (0, 30, 60)]
    scale = resolve_time_scale(records, record_timestamp, timedelta(minutes=180))
    assert scale == pytest.approx(3.0)  # 60 real minutes stretched to fill 180


def test_resolve_time_scale_single_record_is_one():
    assert resolve_time_scale([_record(BASE.isoformat())], record_timestamp, timedelta(minutes=180)) == 1.0


def test_simulated_to_wall_clock_endpoints():
    started_at = datetime(2026, 8, 27, 20, 0, 0, tzinfo=timezone.utc)
    window_start = started_at - timedelta(minutes=180)  # placeholder value, only the delta matters
    duration = 180.0
    compression = (180 * 60) / duration  # 60x

    # A record simulated exactly at window_start emits at the run's start...
    assert simulated_to_wall_clock(window_start, window_start, started_at, compression) == started_at
    # ...and one simulated 180 minutes later (the window's end) emits when
    # the run finishes -- the last event of a replay is always stamped "now".
    window_end = window_start + timedelta(minutes=180)
    assert simulated_to_wall_clock(window_end, window_start, started_at, compression) == started_at + timedelta(
        seconds=duration
    )


def test_build_schedule_is_globally_sorted_across_segments():
    noise = [_record((BASE + timedelta(seconds=s)).isoformat()) for s in range(0, 60, 5)]
    attack = [_record((BASE + timedelta(seconds=s)).isoformat()) for s in (0, 3, 9)]

    segments = [
        SegmentInput(id="noise", records=noise, offset_minutes=-180, time_scale=None),
        SegmentInput(id="attack", records=attack, offset_minutes=-95, time_scale=20.0),
    ]
    started_at = datetime(2026, 8, 27, 20, 0, 0, tzinfo=timezone.utc)

    schedule = build_schedule(segments, record_timestamp, window_minutes=180, duration_seconds=180, started_at=started_at)

    timestamps = [item.timestamp for item in schedule]
    assert timestamps == sorted(timestamps)
    assert all(isinstance(item, ScheduledRecord) for item in schedule)
    assert len(schedule) == len(noise) + len(attack)


def test_build_schedule_last_record_emits_at_run_end():
    # A single-record segment anchored at the window's end (offset 0).
    records = [_record(BASE.isoformat())]
    segments = [SegmentInput(id="tail", records=records, offset_minutes=0, time_scale=1.0)]
    started_at = datetime(2026, 8, 27, 20, 0, 0, tzinfo=timezone.utc)

    schedule = build_schedule(segments, record_timestamp, window_minutes=180, duration_seconds=180, started_at=started_at)

    assert schedule[0].emit_at == started_at + timedelta(seconds=180)


def test_build_schedule_first_record_emits_at_run_start():
    records = [_record(BASE.isoformat())]
    segments = [SegmentInput(id="head", records=records, offset_minutes=-180, time_scale=1.0)]
    started_at = datetime(2026, 8, 27, 20, 0, 0, tzinfo=timezone.utc)

    schedule = build_schedule(segments, record_timestamp, window_minutes=180, duration_seconds=180, started_at=started_at)

    assert schedule[0].emit_at == started_at


def test_build_schedule_skips_empty_segments():
    segments = [SegmentInput(id="empty", records=[], offset_minutes=-180, time_scale=1.0)]
    schedule = build_schedule(
        segments, record_timestamp, window_minutes=180, duration_seconds=180, started_at=BASE
    )
    assert schedule == []
