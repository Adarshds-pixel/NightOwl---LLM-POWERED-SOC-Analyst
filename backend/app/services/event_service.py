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
from datetime import datetime

from sqlalchemy import exists, func, or_, select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.event import Event
from app.schemas.event import NormalizedEvent
from app.services import severity_service

logger = logging.getLogger(__name__)


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
        process=normalized.process,
        command_line=normalized.command_line,
        user=normalized.user,
        raw_json={"raw": normalized.raw, "normalized": normalized.model_dump(mode="json")},
    )
    db.add(event)
    return event


def save_events(db: Session, events: list[NormalizedEvent]) -> list[Event]:
    """Persists a batch of normalized events in a single commit."""
    if not events:
        return []
    rows = [create_event(db, event) for event in events]
    db.commit()
    logger.info("ingested %d events", len(rows))
    return rows


def _filtered_events_stmt(
    host: str | None,
    start_date: datetime | None,
    end_date: datetime | None,
    alert_only: bool | None,
    q: str | None = None,
    severity: str | None = None,
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
    would actually search by hand (process, command line, user, host) --
    backing the frontend's global search box. Deliberately a LIKE rather
    than full-text: the dataset is a single analyst's ingested EVTX files,
    not a multi-tenant log lake, so an index-free scan is fine and it works
    identically on Postgres and the SQLite used in tests.
    """
    stmt = select(Event)
    if host is not None:
        stmt = stmt.where(Event.host == host)
    if q:
        pattern = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(
                Event.process.ilike(pattern),
                Event.command_line.ilike(pattern),
                Event.user.ilike(pattern),
                Event.host.ilike(pattern),
            )
        )
    if start_date is not None:
        stmt = stmt.where(Event.timestamp >= start_date)
    if end_date is not None:
        stmt = stmt.where(Event.timestamp <= end_date)
    if alert_only is True:
        stmt = stmt.where(exists().where(Alert.event_id == Event.id))
    elif alert_only is False:
        stmt = stmt.where(~exists().where(Alert.event_id == Event.id))
    if severity is not None:
        stmt = stmt.where(exists().where((Alert.event_id == Event.id) & (Alert.severity == severity)))
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
) -> list[Event]:
    """Newest-first raw event list for `GET /events`, the full ingested
    timeline -- unlike `GET /incidents`, this includes events that never
    triggered a rule, so the frontend can show the real signal-to-noise
    ratio (e.g. "64,558 events processed, 8 flagged").
    """
    stmt = _filtered_events_stmt(host, start_date, end_date, alert_only, q, severity).order_by(
        Event.timestamp.desc()
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
) -> int:
    """Total events matching the same filters as list_events, ignoring
    limit/offset -- lets `GET /events` report a page-independent `total`
    alongside the page of results.
    """
    subq = _filtered_events_stmt(host, start_date, end_date, alert_only, q, severity).subquery()
    return db.scalar(select(func.count()).select_from(subq)) or 0


def _filtered_alerts_stmt(
    host: str | None,
    start_date: datetime | None,
    end_date: datetime | None,
    severity: str | None,
    q: str | None,
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
    limit: int | None = None,
    offset: int = 0,
) -> list[tuple[Alert, Event]]:
    """Newest-first (Alert.matched_at desc) list of (Alert, Event) pairs for
    `GET /alerts` -- the real "every rule match" feed. Ordered by
    matched_at, not Event.timestamp, so it agrees with how an incident's own
    evidence list (`get_incident_alerts_with_events`) is already ordered.
    """
    stmt = _filtered_alerts_stmt(host, start_date, end_date, severity, q).order_by(Alert.matched_at.desc())
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
) -> int:
    """Total alerts matching the same filters as list_alert_rows, ignoring
    limit/offset -- lets GET /alerts report a page-independent `total` that
    always equals the sum of every incident's evidence-list length, since
    both read from the same un-collapsed Alert rows.
    """
    subq = _filtered_alerts_stmt(host, start_date, end_date, severity, q).subquery()
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
    alerts = list(db.scalars(select(Alert).where(Alert.event_id.in_(event_ids))))
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
    the fields normalization didn't flatten (ParentImage, Hashes,
    network 5-tuple, ...).
    """
    return db.get(Event, event_id)
