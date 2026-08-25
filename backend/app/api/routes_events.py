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

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.detection.rule_loader import get_loaded_rules
from app.services.event_service import count_events, get_alerts_for_event_ids, list_events

router = APIRouter()


class EventLogRow(BaseModel):
    id: int
    host: str
    timestamp: datetime
    event_id: int
    process: str | None
    command_line: str | None
    user: str | None
    is_alert: bool
    severity: str | None = None
    rule_title: str | None = None
    technique_id: str | None = None


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
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> EventListResponse:
    events = list_events(
        db, host=host, start_date=start_date, end_date=end_date, alert_only=alert_only, limit=limit, offset=offset
    )
    total = count_events(db, host=host, start_date=start_date, end_date=end_date, alert_only=alert_only)

    alerts_by_event_id = get_alerts_for_event_ids(db, [event.id for event in events])
    rules_by_id = {rule.rule_id: rule for rule in get_loaded_rules()}

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
                process=event.process,
                command_line=event.command_line,
                user=event.user,
                is_alert=alert is not None,
                severity=alert.severity if alert else None,
                rule_title=rule.title if rule else None,
                technique_id=rule.technique_id if rule else None,
            )
        )

    return EventListResponse(events=rows, count=len(rows), total=total, limit=limit, offset=offset)
