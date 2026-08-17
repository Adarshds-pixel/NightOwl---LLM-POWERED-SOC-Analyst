"""Persists detection matches as Alert rows (Vol1 §3.4 layering: routes ->
services -> models/db; mirrors event_service.py's create/save shape).
"""

import logging
from datetime import datetime

from sqlalchemy.orm import Session

from app.detection.engine import RuleMatch
from app.models.alert import Alert

logger = logging.getLogger(__name__)


def create_alert(db: Session, event_id: int, match: RuleMatch, matched_at: datetime) -> Alert:
    """Builds and stages one Alert row (add, no commit -- caller controls
    the transaction boundary). `event_id` must be the persisted Event row's
    DB primary key, not the raw Sysmon/Windows Event ID on NormalizedEvent.
    `severity` is a direct pass-through of the rule's `level` (e.g. "high")
    -- Alert.severity has no enum constraint, so no translation table is
    needed.
    """
    alert = Alert(
        event_id=event_id,
        rule_id=match.rule_id,
        matched_at=matched_at,
        severity=match.level,
    )
    db.add(alert)
    return alert


def save_alerts(db: Session, alert_data: list[tuple[int, RuleMatch, datetime]]) -> list[Alert]:
    """Builds and persists a batch of alerts in a single commit. Each item
    is (event_id, match, matched_at) -- mirrors save_events' shape of
    taking raw inputs and building the rows internally.
    """
    if not alert_data:
        return []
    rows = [create_alert(db, event_id, match, matched_at) for event_id, match, matched_at in alert_data]
    db.commit()
    logger.info("persisted %d alerts", len(rows))
    return rows
