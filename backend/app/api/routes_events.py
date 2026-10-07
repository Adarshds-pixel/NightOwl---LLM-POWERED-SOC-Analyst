"""GET /events -- the full raw event timeline (both ordinary and
alert-triggering events), separate from GET /incidents' alerts-only view.

Real SOC telemetry is almost entirely normal activity with a small number
of genuine detections buried in it; `GET /incidents` alone can't show that
ratio since it only ever surfaces the events that matched a rule. This
route lets the frontend show the real signal-to-noise ratio (e.g.
"64,558 events processed, 8 flagged as suspicious") instead of only ever
displaying the flagged handful.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.detection.rule_loader import get_loaded_rules
from app.detection.synthetic import NON_YAML_RULES
from app.services.event_service import count_events, get_alerts_for_event_ids, get_event, list_events

router = APIRouter()


class EventLogRow(BaseModel):
    id: int
    host: str
    timestamp: datetime
    event_id: int
    # Raw Windows channel -- event ids collide across channels, so a client
    # needs it to label an event correctly.
    channel: str | None = None
    process: str | None
    parent_process: str | None
    command_line: str | None
    user: str | None
    is_alert: bool
    severity: str | None = None
    severity_score: int | None = None
    rule_title: str | None = None
    technique_id: str | None = None
    # The incident this event's alert was grouped into, when it triggered
    # one. Additive field (None for ordinary events), so the frontend's
    # alert views can link a raw detection to its investigation instead of
    # dead-ending on a row.
    incident_id: int | None = None


class EventListResponse(BaseModel):
    events: list[EventLogRow]
    count: int  # items in this page (== len(events))
    total: int  # grand total matching the filters, across all pages
    limit: int
    offset: int


@router.get("/events", response_model=EventListResponse)
def get_events(
    host: str | None = Query(default=None),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    alert_only: bool | None = Query(default=None, description="true = only alert-triggering events, false = only normal events"),
    severity: str | None = Query(default=None, description="only events with an alert of this severity, e.g. 'critical'"),
    q: str | None = Query(
        default=None,
        description="case-insensitive substring match on process, parent process, command line, user or host",
    ),
    covered: bool | None = Query(
        default=None,
        description="true = event's channel/type has rule coverage (matched or not), "
        "false = no loaded rule could ever evaluate this event -- never conflate with alert_only",
    ),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> EventListResponse:
    events = list_events(
        db,
        host=host,
        start_date=start_date,
        end_date=end_date,
        alert_only=alert_only,
        q=q,
        limit=limit,
        offset=offset,
        severity=severity,
        covered=covered,
    )
    total = count_events(
        db,
        host=host,
        start_date=start_date,
        end_date=end_date,
        alert_only=alert_only,
        q=q,
        severity=severity,
        covered=covered,
    )

    alerts_by_event_id = get_alerts_for_event_ids(db, [event.id for event in events])
    # Sequence-detected alerts (detection/sequences.py) carry a rule_id
    # that was never a loaded YAML rule -- merge in their titles/technique
    # ids too, or every such alert would show as "Unknown rule".
    rules_by_id = {rule.rule_id: rule for rule in get_loaded_rules()} | NON_YAML_RULES

    rows = []
    for event in events:
        alert = alerts_by_event_id.get(event.id)
        rule = rules_by_id.get(alert.rule_id) if alert else None
        rows.append(
            EventLogRow(
                id=event.id,
                host=event.host,
                timestamp=event.timestamp,
                event_id=event.event_id,
                channel=event.channel,
                process=event.process,
                parent_process=event.parent_process,
                command_line=event.command_line,
                user=event.user,
                is_alert=alert is not None,
                severity=alert.severity if alert else None,
                severity_score=alert.severity_score if alert else None,
                rule_title=rule.title if rule else None,
                technique_id=rule.technique_id if rule else None,
                incident_id=alert.incident_id if alert else None,
            )
        )

    return EventListResponse(events=rows, count=len(rows), total=total, limit=limit, offset=offset)


class EventDetailResponse(BaseModel):
    """One event with the raw record attached. Separate model from
    EventLogRow because raw_json is far too large to include on every row
    of a 200-item list page -- it is only ever fetched for the single row
    an analyst expanded.
    """

    id: int
    host: str
    timestamp: datetime
    event_id: int
    # Raw Windows channel -- event ids collide across channels, so a client
    # needs it to label an event correctly.
    channel: str | None = None
    process: str | None
    parent_process: str | None
    command_line: str | None
    user: str | None
    is_alert: bool
    severity: str | None = None
    severity_score: int | None = None
    rule_title: str | None = None
    technique_id: str | None = None
    incident_id: int | None = None
    raw: dict | None = None
    normalized: dict | None = None


@router.get("/events/{event_id}", response_model=EventDetailResponse)
def get_event_detail(event_id: int, db: Session = Depends(get_db)) -> EventDetailResponse:
    event = get_event(db, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail=f"event {event_id} not found")

    alert = get_alerts_for_event_ids(db, [event.id]).get(event.id)
    rules_by_id = {r.rule_id: r for r in get_loaded_rules()} | NON_YAML_RULES
    rule = rules_by_id.get(alert.rule_id) if alert else None
    # create_event stores {"raw": ..., "normalized": ...}; tolerate a row
    # written before that shape existed rather than 500-ing on it.
    payload = event.raw_json if isinstance(event.raw_json, dict) else {}

    return EventDetailResponse(
        id=event.id,
        host=event.host,
        timestamp=event.timestamp,
        event_id=event.event_id,
                channel=event.channel,
        process=event.process,
        parent_process=event.parent_process,
        command_line=event.command_line,
        user=event.user,
        is_alert=alert is not None,
        severity=alert.severity if alert else None,
        severity_score=alert.severity_score if alert else None,
        rule_title=rule.title if rule else None,
        technique_id=rule.technique_id if rule else None,
        incident_id=alert.incident_id if alert else None,
        raw=payload.get("raw") if isinstance(payload.get("raw"), dict) else None,
        normalized=payload.get("normalized") if isinstance(payload.get("normalized"), dict) else None,
    )
