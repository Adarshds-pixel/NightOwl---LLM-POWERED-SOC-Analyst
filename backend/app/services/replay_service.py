"""Runs a demo scenario against wall-clock time, on a background thread
owned by this process.

Why a thread, not FastAPI BackgroundTasks or an asyncio task: BackgroundTasks
would hold a threadpool worker for the whole 2-3 minute run and its
exceptions vanish silently; an asyncio task sharing the single event loop
would visibly stall every other request (`GET /events`, `GET /incidents`,
...) the first time it makes a blocking sync SQLAlchemy call, which is every
tick. A plain daemon `threading.Thread` runs independently of the request/
response cycle -- closing the browser tab, or the examiner's laptop
sleeping, does not kill an in-progress replay.

The one rule that matters for correctness: the worker NEVER reuses the
`Session` from whatever request started it (that session is closed by
`get_db`'s `finally` the instant `/demo/replay/start` responds, and a
`Session` is not thread-safe to share across threads regardless). It opens
a fresh session per tick via an injected `session_factory`, which is also
what lets tests drive this without a real thread or a real database -- see
`emit_due_records`, the pure-enough core this whole module exists to make
testable.
"""

import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import SessionLocal
from app.demo.scenario_loader import ScenarioLoadError, get_loaded_scenario, load_segment_records
from app.demo.timeline import ScheduledRecord, SegmentInput, build_schedule, record_timestamp
from app.detection.rule_loader import LoadedRule, get_loaded_rules
from app.services.ingest_service import ingest_records

logger = logging.getLogger(__name__)


class ReplayAlreadyRunningError(Exception):
    pass


class ReplayNotRunningError(Exception):
    pass


@dataclass
class ReplayRun:
    run_id: str
    scenario_id: str
    scenario_title: str
    state: str  # "running" | "finished" | "stopped" | "failed"
    started_at: datetime
    duration_seconds: float
    window_minutes: float
    records_total: int
    records_emitted: int = 0
    events_ingested: int = 0
    alerts_created: int = 0
    incident_ids: list[int] = field(default_factory=list)
    matched_rule_titles: list[str] = field(default_factory=list)
    current_segment_id: str | None = None
    finished_at: datetime | None = None
    error: str | None = None


# Process-global, guarded by _lock -- same posture as core/rate_limit.py's
# _buckets and rag/cache.py's caches, both already reset per test by
# tests/conftest.py fixtures (this module gets the same treatment, see
# reset_replay_state).
_lock = threading.Lock()
_current: ReplayRun | None = None
_stop_event: threading.Event | None = None


def get_current_run() -> ReplayRun | None:
    with _lock:
        return _current


def reset_replay_state() -> None:
    """Test-only hook: clears process-global state between tests. Mirrors
    `core.rate_limit.reset_rate_limiter`."""
    global _current, _stop_event
    with _lock:
        if _stop_event is not None:
            _stop_event.set()
        _current = None
        _stop_event = None


def _load_records_by_segment(scenario) -> dict[str, list[dict]]:
    return {segment.id: load_segment_records(segment) for segment in scenario.segments}


def build_run_schedule(scenario_id: str, started_at: datetime) -> tuple[object, list[ScheduledRecord]]:
    """Loads a scenario and builds its wall-clock schedule. Split out from
    `start_replay` so scenario/schedule problems (a missing records file, a
    malformed manifest) surface before any thread is spawned or any run is
    recorded as started.
    """
    scenario = get_loaded_scenario(scenario_id)
    records_by_segment = _load_records_by_segment(scenario)

    segments = [
        SegmentInput(
            id=segment.id,
            records=records_by_segment[segment.id],
            offset_minutes=segment.offset_minutes,
            time_scale=segment.time_scale,
        )
        for segment in scenario.segments
    ]
    schedule = build_schedule(
        segments,
        record_timestamp,
        window_minutes=scenario.window_minutes,
        duration_seconds=scenario.duration_seconds,
        started_at=started_at,
    )
    return scenario, schedule


def emit_due_records(
    db: Session,
    run: ReplayRun,
    schedule: list[ScheduledRecord],
    cursor: int,
    now: datetime,
    rules: list[LoadedRule] | None = None,
) -> int:
    """Ingests every scheduled record whose `emit_at <= now`, starting at
    `cursor`, folding the resulting counts into `run` in place. Returns the
    new cursor.

    Pure enough to be the whole test surface for replay behaviour: given a
    schedule, a fake `now`, and a session, this does exactly what one tick
    of the background loop does -- no thread, no sleep, no real clock.
    Records are ingested one at a time (not batched) so `run` reflects
    partial progress even if a later record in the same tick were to fail.
    """
    if rules is None:
        rules = get_loaded_rules()

    due = [item for item in schedule[cursor:] if item.emit_at <= now]
    if not due:
        return cursor

    for item in due:
        outcome = ingest_records(db, [item.record], rules=rules, matched_at=None)
        db.commit()

        run.records_emitted += 1
        run.events_ingested += outcome.events_ingested
        run.alerts_created += outcome.alerts_created
        run.current_segment_id = item.segment_id
        for title in outcome.matched_rule_titles:
            if title not in run.matched_rule_titles:
                run.matched_rule_titles.append(title)
        for incident_id in outcome.incident_ids:
            if incident_id not in run.incident_ids:
                run.incident_ids.append(incident_id)

    return cursor + len(due)


def _spawn_worker_thread(target: Callable[[], None]) -> None:
    threading.Thread(target=target, daemon=True, name="nightowl-replay").start()


def start_replay(
    scenario_id: str,
    session_factory: Callable[[], Session] = SessionLocal,
    spawn: Callable[[Callable[[], None]], None] = _spawn_worker_thread,
) -> ReplayRun:
    """Starts a replay. Raises `ReplayAlreadyRunningError` if one is already
    in progress -- callers (the route) are expected to translate that to a
    409, and to have called `reset_demo_data` first if a clean run matters
    (see `services/demo_service.py`'s docstring on why a stale row from an
    earlier run can silently absorb this run's alerts).

    `spawn` is injected so tests can assert the start contract (state
    transitions to "running", the run is recorded) without ever starting a
    real thread -- pass a no-op and drive `emit_due_records` directly
    instead.
    """
    global _current, _stop_event

    with _lock:
        if _current is not None and _current.state == "running":
            raise ReplayAlreadyRunningError(f"replay {_current.run_id} is already running")

        started_at = datetime.now(timezone.utc)
        try:
            scenario, schedule = build_run_schedule(scenario_id, started_at)
        except ScenarioLoadError as e:
            raise ValueError(str(e)) from e

        run = ReplayRun(
            run_id=uuid.uuid4().hex,
            scenario_id=scenario.id,
            scenario_title=scenario.title,
            state="running",
            started_at=started_at,
            duration_seconds=scenario.duration_seconds,
            window_minutes=scenario.window_minutes,
            records_total=len(schedule),
        )
        _current = run
        stop_event = threading.Event()
        _stop_event = stop_event

    spawn(lambda: _run_loop(run, schedule, session_factory, stop_event))
    return run


def stop_replay() -> ReplayRun | None:
    with _lock:
        run = _current
        stop_event = _stop_event
        if run is None or run.state != "running":
            return run
        if stop_event is not None:
            stop_event.set()
    return run


def _run_loop(
    run: ReplayRun,
    schedule: list[ScheduledRecord],
    session_factory: Callable[[], Session],
    stop_event: threading.Event,
) -> None:
    cursor = 0
    rules = get_loaded_rules()
    tick_seconds = settings.demo_replay_tick_seconds

    try:
        while cursor < len(schedule) and not stop_event.is_set():
            with session_factory() as db:
                cursor = emit_due_records(db, run, schedule, cursor, datetime.now(timezone.utc), rules)
            stop_event.wait(tick_seconds)
    except Exception as exc:  # noqa: BLE001 -- a replay failure must be visible, not swallowed
        run.state = "failed"
        run.error = f"{type(exc).__name__}: {exc}"
        logger.exception("replay run %s failed", run.run_id)
    else:
        run.state = "stopped" if stop_event.is_set() else "finished"
    finally:
        run.finished_at = datetime.now(timezone.utc)
        logger.info(
            "replay run %s %s: %d/%d records emitted, %d alerts, %d incidents",
            run.run_id, run.state, run.records_emitted, run.records_total, run.alerts_created, len(run.incident_ids),
        )
