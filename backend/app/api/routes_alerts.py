"""GET /alerts -- every real rule match, one row per Alert record.

Distinct, on purpose, from `GET /events?alert_only=true`: that route
intentionally collapses to one row per *event* (an event that trips two
rules shows once there, carrying whichever alert `get_alerts_for_event_ids`
picked) -- correct for a raw log timeline, wrong for a page whose entire job
is "every rule match, newest first" (the Alerts page's own subtitle). This
endpoint is that page's real data source: one row per Alert, in exactly the
shape `GET /incidents/{id}`'s evidence list already uses for an incident's
alerts, so an incident's evidence count and the Alerts page total can never
disagree again -- both now read the same, un-collapsed `alerts` rows.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.detection.rule_loader import get_loaded_rules
from app.detection.synthetic import NON_YAML_RULES
from app.services.event_service import count_alert_rows, list_alert_rows

router = APIRouter()


class AlertRow(BaseModel):
    alert_id: int
    # Kept named `id`, meaning the underlying Event's row id -- matches
    # EventLogRow's field of the same name/meaning, so frontend code that
    # already reads `.id` to deep-link into the Logs page needs no changes.
    id: int
    host: str
    timestamp: datetime
    event_id: int
    process: str | None
    parent_process: str | None
    command_line: str | None
    user: str | None
    is_alert: bool = True
    severity: str
    severity_score: int
    rule_title: str
    technique_id: str | None
    incident_id: int | None


class AlertListResponse(BaseModel):
    alerts: list[AlertRow]
    count: int
    total: int
    limit: int
    offset: int


@router.get("/alerts", response_model=AlertListResponse)
def get_alerts(
    host: str | None = Query(default=None),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    severity: str | None = Query(default=None, description="only alerts of this severity, e.g. 'critical'"),
    q: str | None = Query(
        default=None,
        description="case-insensitive substring match on process, parent process, command line, user or host",
    ),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> AlertListResponse:
    rows = list_alert_rows(db, host=host, start_date=start_date, end_date=end_date, severity=severity, q=q, limit=limit, offset=offset)
    total = count_alert_rows(db, host=host, start_date=start_date, end_date=end_date, severity=severity, q=q)
    # Sequence-detected alerts (detection/sequences.py) carry a rule_id
    # that was never a loaded YAML rule -- merge in their titles/technique
    # ids too, or every such alert would show as "Unknown rule".
    rules_by_id = {rule.rule_id: rule for rule in get_loaded_rules()} | NON_YAML_RULES

    result = []
    for alert, event in rows:
        rule = rules_by_id.get(alert.rule_id)
        result.append(
            AlertRow(
                alert_id=alert.id,
                id=event.id,
                host=event.host,
                timestamp=event.timestamp,
                event_id=event.event_id,
                process=event.process,
                parent_process=event.parent_process,
                command_line=event.command_line,
                user=event.user,
                severity=alert.severity,
                severity_score=alert.severity_score,
                rule_title=rule.title if rule else "Unknown rule",
                technique_id=rule.technique_id if rule else None,
                incident_id=alert.incident_id,
            )
        )

    return AlertListResponse(alerts=result, count=len(result), total=total, limit=limit, offset=offset)
