"""Groups related alerts into incidents (Day 9): same host, within a
GROUPING_WINDOW of each other, reuse the same open incident instead of
creating a new one per alert -- mirrors event_service.py/detection_service.py's
create/save layering (routes -> services -> models/db).

The `mitre_technique_ids` merge in find_or_create_incident below already
satisfies Day 11's "roll up technique IDs from an incident's alerts" --
no separate Day 11 change needed here, see docs/decisions.md.

Day 12 adds the two read paths behind `GET /incidents` and
`GET /incidents/{id}` (api/routes_incidents.py): `list_incidents` (filtered,
newest first) and `get_incident_alerts_with_events` (an incident's alerts
joined to their originating event, for the detail view).
"""

import logging
from datetime import datetime, timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.detection.engine import RuleMatch
from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import Incident
from app.services import severity_service

logger = logging.getLogger(__name__)

GROUPING_WINDOW = timedelta(hours=1)


def find_or_create_incident(db: Session, host: str, matched_at: datetime, match: RuleMatch) -> Incident:
    """Finds the most recent open incident for `host` whose `created_at` is
    within GROUPING_WINDOW of `matched_at` and merges this match into it
    (technique id added to `mitre_technique_ids` if new, severity bumped to
    whichever is higher); otherwise creates a new incident. Does not commit
    -- caller controls the transaction boundary (same pattern as
    event_service.create_event/detection_service.create_alert).
    """
    existing = db.scalars(
        select(Incident)
        .where(Incident.host == host)
        .where(Incident.status == "open")
        .where(Incident.created_at >= matched_at - GROUPING_WINDOW)
        .where(Incident.created_at <= matched_at + GROUPING_WINDOW)
        .order_by(Incident.created_at.desc())
    ).first()

    if existing is not None:
        if match.technique_id and match.technique_id not in existing.mitre_technique_ids:
            existing.mitre_technique_ids = [*existing.mitre_technique_ids, match.technique_id]
        existing.severity = severity_service.higher_severity(existing.severity, match.level)
        return existing

    incident = Incident(
        title=f"{match.title} on {host}",
        status="open",
        severity=match.level,
        mitre_technique_ids=[match.technique_id] if match.technique_id else [],
        created_at=matched_at,
        host=host,
    )
    db.add(incident)
    db.flush()  # assign incident.id without committing the whole transaction yet
    logger.info("created incident %d for host %s", incident.id, host)
    return incident


def _filtered_incidents_stmt(
    severity: str | None,
    status: str | None,
    start_date: datetime | None,
    end_date: datetime | None,
    q: str | None = None,
):
    """Shared by list_incidents and count_incidents so the two never drift
    out of sync -- every filter is optional and additive (AND'd together).
    `q` is a case-insensitive substring match on title/host, backing the
    frontend's global search; same LIKE-not-full-text reasoning as
    event_service._filtered_events_stmt.
    """
    stmt = select(Incident)
    if q:
        pattern = f"%{q.strip()}%"
        stmt = stmt.where(or_(Incident.title.ilike(pattern), Incident.host.ilike(pattern)))
    if severity is not None:
        stmt = stmt.where(Incident.severity == severity)
    if status is not None:
        stmt = stmt.where(Incident.status == status)
    if start_date is not None:
        stmt = stmt.where(Incident.created_at >= start_date)
    if end_date is not None:
        stmt = stmt.where(Incident.created_at <= end_date)
    return stmt


def list_incidents(
    db: Session,
    severity: str | None = None,
    status: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    q: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> list[Incident]:
    """Newest-first incident list for `GET /incidents`, filtered by any
    combination of severity/status/created_at date range, with optional
    limit/offset pagination (Day 13). `limit=None` (the default for direct
    callers) returns every match, unpaginated; the route always passes an
    explicit limit.
    """
    stmt = _filtered_incidents_stmt(severity, status, start_date, end_date, q).order_by(Incident.created_at.desc())
    if limit is not None:
        stmt = stmt.limit(limit).offset(offset)
    return list(db.scalars(stmt))


def count_incidents(
    db: Session,
    severity: str | None = None,
    status: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    q: str | None = None,
) -> int:
    """Total incidents matching the same filters as list_incidents, ignoring
    limit/offset -- lets `GET /incidents` report a page-independent `total`
    (Day 13) alongside the page of results.
    """
    subq = _filtered_incidents_stmt(severity, status, start_date, end_date, q).subquery()
    return db.scalar(select(func.count()).select_from(subq)) or 0


def get_incident_alerts_with_events(db: Session, incident_id: int) -> list[tuple[Alert, Event]]:
    """An incident's alerts joined to the event each one fired on, for
    `GET /incidents/{id}`'s detail view -- avoids a separate query per alert
    to fetch its event.
    """
    stmt = (
        select(Alert, Event)
        .join(Event, Alert.event_id == Event.id)
        .where(Alert.incident_id == incident_id)
        .order_by(Alert.matched_at)
    )
    return [(alert, event) for alert, event in db.execute(stmt)]
