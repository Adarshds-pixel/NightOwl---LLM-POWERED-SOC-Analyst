"""Persists detection matches as Alert rows (Vol1 §3.4 layering: routes ->
services -> models/db; mirrors event_service.py's create/save shape).
"""

import logging
from datetime import datetime

from sqlalchemy.orm import Session

from app.detection.engine import RuleMatch
from app.models.alert import Alert

logger = logging.getLogger(__name__)


def create_alert(
    db: Session,
    event_id: int,
    match: RuleMatch,
    matched_at: datetime,
    incident_id: int | None = None,
) -> Alert:
    """Builds and stages one Alert row (add, no commit -- caller controls
    the transaction boundary). `event_id` must be the persisted Event row's
    DB primary key, not the raw Sysmon/Windows Event ID on NormalizedEvent.
    `severity` is a direct pass-through of `match.level`, which is already
    the final tactic-weighted severity by the time it reaches here (Day 10,
    see engine.evaluate_event/severity_service.py) -- no translation table
    needed. `incident_id` is optional so alert persistence never depends on
    grouping having succeeded.
    """
    alert = Alert(
        event_id=event_id,
        rule_id=match.rule_id,
        matched_at=matched_at,
        severity=match.level,
        severity_score=match.score,
        incident_id=incident_id,
    )
    db.add(alert)
    return alert


def save_alerts(db: Session, alert_data: list[tuple[int, RuleMatch, datetime, int | None]]) -> list[Alert]:
    """Builds and persists a batch of alerts in a single commit. Each item
    is (event_id, match, matched_at, incident_id) -- mirrors save_events'
    shape of taking raw inputs and building the rows internally.
    """
    if not alert_data:
        return []
    rows = [
        create_alert(db, event_id, match, matched_at, incident_id)
        for event_id, match, matched_at, incident_id in alert_data
    ]
    db.commit()
    logger.info("persisted %d alerts", len(rows))
    return rows
