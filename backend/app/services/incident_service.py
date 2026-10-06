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
from app.detection.rule_loader import get_loaded_rules
from app.detection.sequences import SEQUENCE_PATTERNS
from app.detection.synthetic import NON_YAML_RULES
from app.ml.rule import ML_RULE_ID
from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import Incident
from app.services import event_service, severity_service

logger = logging.getLogger(__name__)

GROUPING_WINDOW = timedelta(hours=1)

# Evidence-first alerts (pending.md item 5): a narrow window around an
# alert's own event, not the full 1h GROUPING_WINDOW incidents are grouped
# on -- "what else happened right around this" is investigative context,
# not every event this incident's grouping window happens to span.
RELATED_EVENTS_WINDOW = timedelta(minutes=5)
RELATED_EVENTS_LIMIT = 5


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
        existing.severity_score = max(existing.severity_score, match.score)
        return existing

    incident = Incident(
        title=f"{match.title} on {host}",
        status="open",
        severity=match.level,
        severity_score=match.score,
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


def get_related_events(db: Session, host: str, around: datetime, exclude_event_id: int) -> list[Event]:
    """Up to RELATED_EVENTS_LIMIT other events on `host` within
    RELATED_EVENTS_WINDOW of `around` (an alert's own event timestamp) --
    the investigative context an analyst would otherwise only get by
    switching to the Logs page and filtering by hand. Reuses
    event_service.list_events() (the same query GET /events runs) rather
    than a new query shape, per this item's "no new subsystem" scope.
    """
    window_start = around - RELATED_EVENTS_WINDOW
    window_end = around + RELATED_EVENTS_WINDOW
    # +1 so excluding the alert's own event (almost always inside the
    # window) still leaves up to RELATED_EVENTS_LIMIT real neighbors.
    candidates = event_service.list_events(
        db, host=host, start_date=window_start, end_date=window_end, limit=RELATED_EVENTS_LIMIT + 1
    )
    return [event for event in candidates if event.id != exclude_event_id][:RELATED_EVENTS_LIMIT]


def build_incident_evidence(db: Session, incident: Incident) -> dict:
    """The bounded evidence package rag/explain_service.py's and
    rag/chat_service.py's LLM prompts are built from (pending.md item 5:
    "extend the evidence input beyond {title, severity, host,
    technique_id}"). Reuses get_incident_alerts_with_events/
    get_related_events above -- the exact same lookups `GET
    /incidents/{id}` already runs to build its own per-alert evidence
    list -- rather than a new query shape, so this is wiring the LLM
    prompt to data that already exists, not a new lookup.

    Bounded to the incident's FIRST alert (earliest matched_at), not
    every alert it has: some incidents carry dozens of near-duplicate
    alerts from the same rule (e.g. "Remote Thread Creation" firing once
    per CreateRemoteThread event in a file) -- dumping all of them into
    the prompt would balloon its size without adding real signal, so any
    additional alerts are only counted, not individually detailed.
    """
    evidence: dict = {
        "description": incident.title,
        "severity": incident.severity,
        "host": incident.host,
        "technique_id": incident.mitre_technique_ids[0] if incident.mitre_technique_ids else None,
        "technique_ids": incident.mitre_technique_ids or [],
    }

    alerts_with_events = get_incident_alerts_with_events(db, incident.id)
    if not alerts_with_events:
        return evidence

    primary_alert, primary_event = alerts_with_events[0]
    # Merges in the detectors that have no YAML file behind them the same way
    # get_incident_detail's own rules_by_id does -- a sequence's rule_id
    # (detection/sequences.py) and the ML layer's (app/ml/rule.py) were never
    # loaded YAML rules, so they would otherwise resolve to no title at all.
    rules_by_id = {rule.rule_id: rule for rule in get_loaded_rules()} | NON_YAML_RULES
    rule = rules_by_id.get(primary_alert.rule_id)

    evidence["matched_rule"] = rule.title if rule else None
    if primary_alert.rule_id in SEQUENCE_PATTERNS:
        evidence["detection_method"] = "multi-event sequence correlation"
    elif primary_alert.rule_id == ML_RULE_ID:
        # Naming this honestly matters downstream: the RAG explanation layer
        # reads detection_method, and an anomaly score is not a rule match.
        evidence["detection_method"] = "unsupervised behavioural anomaly (no specific technique)"
    else:
        evidence["detection_method"] = "single-event Sigma rule"
    evidence["process"] = primary_event.process
    evidence["parent_process"] = primary_event.parent_process
    evidence["command_line"] = primary_event.command_line
    evidence["user"] = primary_event.user

    related = get_related_events(
        db, host=primary_event.host, around=primary_event.timestamp, exclude_event_id=primary_event.id
    )
    if related:
        evidence["related_events"] = [
            f"{event.timestamp.isoformat()} event_id={event.event_id} "
            f"process={event.process or 'unknown'} command_line={event.command_line or 'none'}"
            for event in related
        ]

    if len(alerts_with_events) > 1:
        evidence["additional_alerts"] = (
            f"{len(alerts_with_events) - 1} more alert(s) matched on this incident, not individually listed here"
        )

    return evidence
