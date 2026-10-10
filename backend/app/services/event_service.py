"""Persists NormalizedEvent schemas as Event rows (Vol1 §3.4 layering:
routes -> services -> models/db; this is the only place that talks to the
DB for events).

list_events/count_events (GET /events, the raw event-timeline endpoint --
alerts only ever show the small fraction of events that matched a rule,
this shows everything ingested) follow incident_service.py's
_filtered_*_stmt + list_*/count_* pattern exactly, so the two queries can't
drift out of sync on their filters.
"""

import logging
from collections import defaultdict
from datetime import datetime

from sqlalchemy import and_, exists, false, func, or_, select
from sqlalchemy.orm import Session

from app.detection.coverage import DEFAULT_ROUTINE_CHANNELS, ROUTINE_EVENTS, checked_pairs
from app.detection.rule_loader import get_loaded_rules
from app.ingestion.normalizer import CHANNEL_PATTERNS
from app.ml.rule import ML_RULE_ID
from app.models.alert import Alert
from app.models.event import Event
from app.schemas.event import NormalizedEvent
from app.services import severity_service

logger = logging.getLogger(__name__)


def fit(value: str | None, limit: int) -> str | None:
    """Clip a value to its column width. Postgres rejects an over-long VARCHAR
    with a DataError that rolls back the *whole* upload, so one event with a
    600-character image path (which an attacker can plant on purpose) used to
    keep an entire log out of NightOwl. The full value is still kept in
    raw_json; only the flat, searchable column is clipped."""
    if value is None or len(value) <= limit:
        return value
    return value[: limit - 1] + "\u2026"


def create_event(db: Session, normalized: NormalizedEvent) -> Event:
    """Builds and stages one Event row (add, no commit -- caller controls
    the transaction boundary; Day 6's ingest endpoint commits once per
    upload). raw_json keeps both the original raw record and the
    normalized view, so fields this module doesn't map onto flat columns
    (e.g. ParentImage, Hashes) aren't lost.
    """
    event = Event(
        host=normalized.host,
        timestamp=normalized.timestamp,
        event_id=normalized.event_id,
        channel=normalized.channel,
        event_record_id=normalized.event_record_id,
        process=fit(normalized.process, 500),
        parent_process=fit(normalized.parent_process, 500),
        command_line=normalized.command_line,
        user=fit(normalized.user, 255),
        raw_json={"raw": normalized.raw, "normalized": normalized.model_dump(mode="json")},
    )
    db.add(event)
    return event


_DEDUP_CHUNK = 500


def find_existing_event_keys(
    db: Session, keys: set[tuple[str, str | None, int]]
) -> set[tuple[str, str | None, int]]:
    """Which of the given (host, channel, event_record_id) triples already
    exist in `events` -- ingest_records() uses this to skip re-inserting an
    event NightOwl has already ingested (the same EVTX file, or a
    re-export overlapping an earlier one, uploaded twice), instead of
    silently doubling every event/alert/incident-derived KPI. A Windows
    event's own EventRecordID is a real identity assigned by Windows
    itself, not something NightOwl invents (see models/event.py).

    One query for the whole ingest batch, not one per event: narrows on
    the batch's own hosts + record ids first (both indexed, see
    `ix_events_dedup_key`), then the exact-triple match happens in Python
    over that already-small result set.
    """
    if not keys:
        return set()
    hosts = {host for host, _channel, _record_id in keys}
    record_ids = sorted({record_id for _host, _channel, record_id in keys})
    # Chunked: one IN list with every record id of a 50,000-record capture
    # exceeds SQLite's bound-parameter limit (32,766) and makes a large upload
    # fail there. A few hundred ids per query is fast on both databases.
    candidates: set[tuple[str, str | None, int]] = set()
    for start in range(0, len(record_ids), _DEDUP_CHUNK):
        chunk = record_ids[start : start + _DEDUP_CHUNK]
        rows = db.execute(
            select(Event.host, Event.channel, Event.event_record_id).where(
                Event.host.in_(hosts), Event.event_record_id.in_(chunk)
            )
        ).all()
        candidates.update((row.host, row.channel, row.event_record_id) for row in rows)
    return candidates & keys


def save_events(db: Session, events: list[NormalizedEvent]) -> list[Event]:
    """Persists a batch of normalized events in a single commit."""
    if not events:
        return []
    rows = [create_event(db, event) for event in events]
    db.flush()
    logger.info("ingested %d events", len(rows))
    return rows


def _pairs_predicate(pairs):
    """SQL expression matching the `Event.channel`/`Event.event_id`
    combinations at least one currently loaded rule covers -- the
    query-time mirror of engine.py's covered_event_ids() +
    normalizer.canonical_channel(). Grouped by channel token rather than a
    flat event_id list, for the same reason covered_event_ids() itself is
    keyed that way: event IDs collide across channels, so "event_id in
    {...}" alone would misclassify a same-numbered event from an
    unrelated channel. `Event.channel` is coalesced to '' before matching
    so a NULL channel (unrecognized/never set) reliably evaluates to
    False rather than SQL's NULL, which would otherwise silently drop
    those rows from *both* `covered=True` and `covered=False` queries.
    """
    by_token: dict[str | None, set[int]] = defaultdict(set)
    for token, event_id in pairs:
        by_token[token].add(event_id)

    channel_col = func.lower(func.trim(func.coalesce(Event.channel, "")))

    def _token_match(token: str):
        exact_names, prefixes = CHANNEL_PATTERNS[token]
        return or_(channel_col.in_(sorted(exact_names)), *(channel_col.like(f"{p}%") for p in prefixes))

    clauses = []
    for token, event_ids in by_token.items():
        if not event_ids:
            continue
        if token is None:
            channel_match = and_(*(~_token_match(t) for t in CHANNEL_PATTERNS))
        else:
            channel_match = _token_match(token)
        clauses.append(and_(channel_match, Event.event_id.in_(event_ids)))
    return or_(*clauses) if clauses else false()


def _covered_predicate():
    """Events a loaded rule or sequence detector evaluates (CHECKED)."""
    return _pairs_predicate(checked_pairs(get_loaded_rules()))


def _routine_predicate():
    """Everyday events that are not CHECKED (see detection/coverage.py)."""
    explicit = {(token, event_id) for token, ids in ROUTINE_EVENTS.items() for event_id in ids}
    clauses = [_pairs_predicate(explicit)]
    for token in DEFAULT_ROUTINE_CHANNELS:
        exact_names, prefixes = CHANNEL_PATTERNS[token]
        channel_col = func.lower(func.trim(func.coalesce(Event.channel, "")))
        clauses.append(or_(channel_col.in_(sorted(exact_names)), *(channel_col.like(f"{p}%") for p in prefixes)))
    return and_(~_covered_predicate(), or_(*clauses))


def _filtered_events_stmt(
    host: str | None,
    start_date: datetime | None,
    end_date: datetime | None,
    alert_only: bool | None,
    q: str | None = None,
    severity: str | None = None,
    covered: bool | None = None,
    coverage: str | None = None,
):
    """Shared by list_events and count_events so the two never drift out of
    sync -- every filter is optional and additive (AND'd together).
    alert_only=True restricts to events with at least one Alert row,
    alert_only=False restricts to events with none, None applies no filter.
    `severity` restricts to events with at least one Alert row of that
    severity -- server-side so a filtered page's `total` is the real total
    for that filter, not the unfiltered one (the frontend previously
    narrowed severity client-side over one page, which made a filtered view
    disagree with its own pagination footer).
    `q` is a case-insensitive substring match across the fields an analyst
    would actually search by hand (process, parent process, command line,
    user, host) -- backing the frontend's global search box. Deliberately
    a LIKE rather than full-text: the dataset is a single analyst's
    ingested EVTX files, not a multi-tenant log lake, so an index-free scan
    is fine and it works identically on Postgres and the SQLite used in
    tests.
    `covered` is the store-wide twin of `alert_only`: True restricts to
    events whose channel+type at least one loaded rule could ever
    evaluate (matched or not), False restricts to events no loaded rule
    could ever have looked at, None applies no filter -- see
    `_covered_predicate()`. Never conflate this with `alert_only=False`:
    an event can be covered and simply not match anything (genuinely
    clean), or uncovered because nothing could evaluate it at all.
    """
    stmt = select(Event)
    if host is not None:
        stmt = stmt.where(Event.host == host)
    if q:
        pattern = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(
                Event.process.ilike(pattern),
                Event.parent_process.ilike(pattern),
                Event.command_line.ilike(pattern),
                Event.user.ilike(pattern),
                Event.host.ilike(pattern),
            )
        )
    if start_date is not None:
        stmt = stmt.where(Event.timestamp >= start_date)
    if end_date is not None:
        stmt = stmt.where(Event.timestamp <= end_date)
    # "Alerting" means a rule/sequence DETECTION -- an ML anomaly record
    # anchored on an event does not make that event a detection.
    detection = (Alert.event_id == Event.id) & (Alert.rule_id != ML_RULE_ID)
    if alert_only is True:
        stmt = stmt.where(exists().where(detection))
    elif alert_only is False:
        stmt = stmt.where(~exists().where(detection))
    if severity is not None:
        stmt = stmt.where(exists().where(detection & (Alert.severity == severity)))
    if covered is True:
        stmt = stmt.where(_covered_predicate())
    elif covered is False:
        stmt = stmt.where(~_covered_predicate())
    # `coverage` is the three-way form of `covered`: "checked" | "routine" |
    # "unchecked" (see detection/coverage.py).
    if coverage == "checked":
        stmt = stmt.where(_covered_predicate())
    elif coverage == "routine":
        stmt = stmt.where(_routine_predicate())
    elif coverage == "unchecked":
        stmt = stmt.where(~_covered_predicate(), ~_routine_predicate())
    return stmt


def list_events(
    db: Session,
    host: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    alert_only: bool | None = None,
    q: str | None = None,
    limit: int | None = None,
    offset: int = 0,
    severity: str | None = None,
    covered: bool | None = None,
    coverage: str | None = None,
) -> list[Event]:
    """Newest-first raw event list for `GET /events`, the full ingested
    timeline -- unlike `GET /incidents`, this includes events that never
    triggered a rule, so the frontend can show the real signal-to-noise
    ratio (e.g. "64,558 events processed, 8 flagged").
    """
    # id as the tiebreaker: EVTX events routinely share a timestamp, and
    # without a total order Postgres may page the same row twice or skip one.
    stmt = _filtered_events_stmt(host, start_date, end_date, alert_only, q, severity, covered, coverage).order_by(
        Event.timestamp.desc(), Event.id.desc()
    )
    if limit is not None:
        stmt = stmt.limit(limit).offset(offset)
    return list(db.scalars(stmt))


def count_events(
    db: Session,
    host: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    alert_only: bool | None = None,
    q: str | None = None,
    severity: str | None = None,
    covered: bool | None = None,
    coverage: str | None = None,
) -> int:
    """Total events matching the same filters as list_events, ignoring
    limit/offset -- lets `GET /events` report a page-independent `total`
    alongside the page of results.
    """
    subq = _filtered_events_stmt(host, start_date, end_date, alert_only, q, severity, covered, coverage).subquery()
    return db.scalar(select(func.count()).select_from(subq)) or 0


def _filtered_alerts_stmt(
    host: str | None,
    start_date: datetime | None,
    end_date: datetime | None,
    severity: str | None,
    q: str | None,
    kind: str | None = None,
):
    """Backs GET /alerts: one row per Alert (joined to its Event), never
    collapsed. This is deliberately a separate statement from
    `_filtered_events_stmt` rather than that query with a different filter --
    `alert_only=True` there restricts *events* to ones with >=1 alert and
    still returns one row per event (correct for a raw log timeline), while
    this restricts and returns *alerts* directly, one row each (correct for
    a page whose job is showing every detection). An event that trips two
    rules produces two rows here and one there, on purpose.
    """
    stmt = select(Alert, Event).join(Event, Alert.event_id == Event.id)
    # "detection" = rule + sequence alerts, "ml" = ML anomaly records.
    if kind == "detection":
        stmt = stmt.where(Alert.rule_id != ML_RULE_ID)
    elif kind == "ml":
        stmt = stmt.where(Alert.rule_id == ML_RULE_ID)
    if host is not None:
        stmt = stmt.where(Event.host == host)
    if severity is not None:
        stmt = stmt.where(Alert.severity == severity)
    if start_date is not None:
        stmt = stmt.where(Event.timestamp >= start_date)
    if end_date is not None:
        stmt = stmt.where(Event.timestamp <= end_date)
    if q:
        pattern = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(
                Event.process.ilike(pattern),
                Event.parent_process.ilike(pattern),
                Event.command_line.ilike(pattern),
                Event.user.ilike(pattern),
                Event.host.ilike(pattern),
            )
        )
    return stmt


def list_alert_rows(
    db: Session,
    host: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    severity: str | None = None,
    q: str | None = None,
    kind: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> list[tuple[Alert, Event]]:
    """Newest-first (Alert.matched_at desc) list of (Alert, Event) pairs for
    `GET /alerts` -- the real "every rule match" feed. Ordered by
    matched_at, not Event.timestamp, so it agrees with how an incident's own
    evidence list (`get_incident_alerts_with_events`) is already ordered.
    """
    stmt = _filtered_alerts_stmt(host, start_date, end_date, severity, q, kind).order_by(
        Alert.matched_at.desc(), Alert.id.desc()
    )
    if limit is not None:
        stmt = stmt.limit(limit).offset(offset)
    return [(alert, event) for alert, event in db.execute(stmt)]


def count_alert_rows(
    db: Session,
    host: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    severity: str | None = None,
    q: str | None = None,
    kind: str | None = None,
) -> int:
    """Total alerts matching the same filters as list_alert_rows, ignoring
    limit/offset -- lets GET /alerts report a page-independent `total` that
    always equals the sum of every incident's evidence-list length, since
    both read from the same un-collapsed Alert rows.
    """
    subq = _filtered_alerts_stmt(host, start_date, end_date, severity, q, kind).subquery()
    return db.scalar(select(func.count()).select_from(subq)) or 0


def get_alerts_for_event_ids(db: Session, event_ids: list[int]) -> dict[int, Alert]:
    """One query for a page of event ids -> {event_id: highest-severity
    Alert}, so `GET /events` can enrich each row with alert status without
    a per-row query. An event can match more than one rule (multiple Alert
    rows sharing an event_id); ties keep whichever alert was seen first,
    since the choice only affects which single severity/rule_id is shown.
    """
    if not event_ids:
        return {}
    alerts = list(
        db.scalars(
            select(Alert)
            .where(Alert.event_id.in_(event_ids), Alert.rule_id != ML_RULE_ID)
            .order_by(Alert.id)
        )
    )
    best: dict[int, Alert] = {}
    for alert in alerts:
        existing = best.get(alert.event_id)
        if existing is None or severity_service.higher_severity(existing.severity, alert.severity) != existing.severity:
            best[alert.event_id] = alert
    return best


def get_event(db: Session, event_id: int) -> Event | None:
    """One event by id, including its raw_json payload -- backs
    `GET /events/{id}`, the Logs page's expandable raw-record view. The
    list endpoint deliberately omits raw_json (it is the largest column by
    far and would dominate a 200-row page), so this is the only way to see
    the fields normalization didn't flatten (Hashes, network 5-tuple, ...;
    ParentImage was promoted onto its own column, see models/event.py).
    """
    return db.get(Event, event_id)
