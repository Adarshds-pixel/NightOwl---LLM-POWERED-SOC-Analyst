"""Groups related alerts into incidents (Day 9): same host, within a
GROUPING_WINDOW of each other, reuse the same open incident instead of
creating a new one per alert -- mirrors event_service.py/detection_service.py's
create/save layering (routes -> services -> models/db).

The `mitre_technique_ids` merge in find_or_create_incident below already
satisfies Day 11's "roll up technique IDs from an incident's alerts" --
no separate Day 11 change needed here, see docs/decisions.md.
"""

import logging
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection.engine import RuleMatch
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
