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


def save_alerts(db: Session, alert_data: list[tuple]) -> list[Alert]:
    """Builds and persists a batch of alerts (flush, no commit). Each item is
    (event_id, match, matched_at, incident_id) or, with extra columns,
    (event_id, match, matched_at, incident_id, extras) where `extras` sets any
    of occurrence_count / last_matched_at / details on the row.
    """
    if not alert_data:
        return []
    rows = []
    for item in alert_data:
        event_id, match, matched_at, incident_id = item[:4]
        alert = create_alert(db, event_id, match, matched_at, incident_id)
        extras = item[4] if len(item) > 4 else None
        if extras:
            for key in ("occurrence_count", "last_matched_at", "details"):
                if key in extras:
                    setattr(alert, key, extras[key])
        rows.append(alert)
    db.flush()
    logger.info("persisted %d alerts", len(rows))
    return rows
