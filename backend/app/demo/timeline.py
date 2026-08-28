"""Pure timestamp-rebasing math for the live replay demo. No DB, no I/O --
every function here is deterministic and takes/returns plain values, so the
whole rebasing contract is unit-testable without a database or a clock.

The rebase is two linked mappings, both linear:

  1. capture time -> simulated time   (per segment: preserve relative
     spacing within the segment, anchored on the segment's declared offset)
  2. simulated time -> wall-clock emit time  (one linear compression across
     the whole scenario: the declared `window_minutes` of simulated activity
     is compressed into `duration_seconds` of real time)

Composing them is what lets an 8-minute-apart pair of attack steps in a real
capture become, say, 75 *simulated* minutes apart (so they land in separate
incidents -- see services/incident_service.py's 1-hour grouping window) while
the whole replay still only takes 3 real minutes on stage.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable

def record_timestamp(record: dict) -> datetime:
    """Reads `Event.System.TimeCreated.@SystemTime` the same way
    `ingestion/normalizer.py`'s `_extract_timestamp` does (same ISO-8601 +
    trailing-`Z` handling), so a segment's records sort here exactly as they
    will once actually normalized. The default `get_timestamp` every real
    caller passes to `rebase_segment`/`build_schedule`; tests are free to
    pass a simpler stand-in since these functions never call this directly.
    """
    raw = record["Event"]["System"]["TimeCreated"]["@SystemTime"]
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


@dataclass(frozen=True)
class ScheduledRecord:
    """One record, ready to be fed to `ingest_service.ingest_records`."""

    record: dict
    """Verbatim source record, with only `System.TimeCreated.@SystemTime`
    rewritten -- see `with_rebased_timestamp`. Every other field (Computer,
    Image, CommandLine, User, the network 5-tuple, ...) is untouched, which
    is what makes "only the timestamp is scripted" a checkable claim rather
    than a promise."""

    timestamp: datetime
    """Rebased *simulated* event time (tz-aware UTC) -- what ends up in
    `Event.timestamp` once ingested."""

    emit_at: datetime
    """Wall-clock moment this record should be fed in."""

    segment_id: str


def with_rebased_timestamp(record: dict, timestamp: datetime) -> dict:
    """Returns a copy of `record` with `Event.System.TimeCreated.@SystemTime`
    rewritten to `timestamp`'s ISO 8601 form. Every other key, including
    every other System/EventData field, is passed through unchanged -- this
    is the one and only field the replay is allowed to alter.
    """
    event = dict(record.get("Event") or {})
    system = dict(event.get("System") or {})
    time_created = dict(system.get("TimeCreated") or {})

    time_created["@SystemTime"] = timestamp.isoformat()
    system["TimeCreated"] = time_created
    event["System"] = system

    rebased = dict(record)
    rebased["Event"] = event
    return rebased


def rebase_segment(
    records: list[dict],
    get_timestamp: Callable[[dict], datetime],
    anchor: datetime,
    time_scale: float = 1.0,
) -> list[tuple[dict, datetime]]:
    """Rebases one segment's records onto simulated time.

    The first record (by capture order, which callers must already have
    sorted ascending) lands exactly on `anchor`. Every later record keeps its
    original delta from the segment's own first record, multiplied by
    `time_scale` -- so `time_scale=1.0` preserves the capture's real pacing
    (e.g. a 29-second burst stays a 29-second burst, just relocated), and
    `time_scale=20` stretches that same 29 seconds into ~10 simulated
    minutes without changing which record came first or their proportions.

    Returns `(record, rebased_timestamp)` pairs, order preserved.
    """
    if not records:
        return []

    first_ts = get_timestamp(records[0])
    rebased: list[tuple[dict, datetime]] = []
    for record in records:
        delta = (get_timestamp(record) - first_ts) * time_scale
        timestamp = anchor + delta
        rebased.append((with_rebased_timestamp(record, timestamp), timestamp))
    return rebased


def resolve_time_scale(
    records: list[dict],
    get_timestamp: Callable[[dict], datetime],
    target_span: timedelta,
) -> float:
    """The multiplier that stretches (or compresses) a segment's own capture
    span to exactly fill `target_span`. Used for a scenario's `time_scale:
    fill` segments -- typically the noise segment, which should cover the
    whole demo window rather than being anchored at one instant.

    A single-record or zero-duration segment has no span to scale, so this
    returns `1.0` for it rather than dividing by zero.
    """
    if len(records) < 2:
        return 1.0
    capture_span = get_timestamp(records[-1]) - get_timestamp(records[0])
    if capture_span <= timedelta(0):
        return 1.0
    return target_span / capture_span


def simulated_to_wall_clock(
    simulated_timestamp: datetime,
    window_start: datetime,
    started_at: datetime,
    compression: float,
) -> datetime:
    """Maps a rebased *simulated* timestamp to the *wall-clock* moment it
    should be emitted at, given the whole scenario compresses
    `window_minutes` of simulated time into `duration_seconds` of real time
    (`compression = window_seconds / duration_seconds`).

    A record simulated exactly at `window_start` emits at `started_at`; one
    simulated at the window's end emits at `started_at + duration_seconds`
    -- i.e. the very last record of a replay always lands stamped as "now"
    at the moment the run finishes, which is the property that makes the
    console read as live rather than as a fast-forwarded recording.
    """
    elapsed_simulated = simulated_timestamp - window_start
    return started_at + elapsed_simulated / compression


@dataclass(frozen=True)
class SegmentInput:
    """One segment's records plus its placement in the scenario timeline.
    A lightweight, scenario_loader-independent shape (this module must stay
    import-free of scenario_loader.py, which itself calls into timeline.py
    to do the rebasing) -- `scenario_loader`/`replay_service` build one of
    these per `ScenarioSegment` they load.
    """

    id: str
    records: list[dict]
    offset_minutes: float
    """Anchor position, in simulated minutes relative to the scenario
    window's END (so -180 is the very start of a 180-minute window, -12 is
    12 simulated minutes before "now"). Negative for anything before the
    window's end, which in practice is every segment."""
    time_scale: float | None
    """`None` means "fill": stretch this segment's own capture span to
    exactly cover the whole simulated window, used by a noise segment that
    should run continuously rather than sit at one anchor."""


def build_schedule(
    segments: list[SegmentInput],
    get_timestamp: Callable[[dict], datetime],
    window_minutes: float,
    duration_seconds: float,
    started_at: datetime,
) -> list[ScheduledRecord]:
    """The one place both rebasing steps (capture -> simulated, simulated ->
    wall clock) are composed. Returns a single list of every segment's
    records, sorted by `timestamp` ascending across segment boundaries.

    Chronological order is a hard precondition of
    `ingest_service.ingest_records(matched_at=None)`'s incident grouping
    (see that function's docstring) -- establishing it here, once, rather
    than trusting every caller to merge segments correctly, is what makes
    that precondition actually hold.
    """
    window_end = started_at + timedelta(seconds=duration_seconds)
    window_start = window_end - timedelta(minutes=window_minutes)
    compression = (window_minutes * 60) / duration_seconds if duration_seconds else 1.0

    scheduled: list[ScheduledRecord] = []
    for segment in segments:
        if not segment.records:
            continue

        anchor = window_start + timedelta(minutes=window_minutes) + timedelta(minutes=segment.offset_minutes)
        time_scale = segment.time_scale
        if time_scale is None:
            remaining = window_end - anchor
            time_scale = resolve_time_scale(segment.records, get_timestamp, remaining)

        for record, sim_ts in rebase_segment(segment.records, get_timestamp, anchor, time_scale):
            emit_at = simulated_to_wall_clock(sim_ts, window_start, started_at, compression)
            scheduled.append(ScheduledRecord(record=record, timestamp=sim_ts, emit_at=emit_at, segment_id=segment.id))

    scheduled.sort(key=lambda item: item.timestamp)
    return scheduled
