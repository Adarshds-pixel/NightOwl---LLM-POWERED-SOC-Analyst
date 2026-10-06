"""Audit log persistence: who/when for incident status changes and
explain/chat calls (Day 13 production hardening). Mirrors
services/chat_service.py's layering -- this file only owns reading/writing
AuditLog rows; routes call it directly, same as they already call
services/chat_service.py's add_message/list_messages.
"""

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog

logger = logging.getLogger(__name__)

DEFAULT_ACTOR = "system"


def record_event(
    db: Session,
    entity_type: str,
    entity_id: int,
    action: str,
    actor: str | None = None,
    details: dict | None = None,
) -> AuditLog:
    """Persist one audit entry. Commits immediately -- each call here is
    already its own complete unit of work, same posture as
    chat_service.add_message."""
    entry = AuditLog(
        entity_type=entity_type,
        entity_id=entity_id,
        action=action,
        actor=actor or DEFAULT_ACTOR,
        details=details,
        created_at=datetime.now(timezone.utc),
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    logger.info(
        "recorded audit event action=%s entity=%s:%d actor=%s", action, entity_type, entity_id, entry.actor
    )
    return entry


def list_events(db: Session, entity_type: str, entity_id: int) -> list[AuditLog]:
    """An entity's audit trail, oldest first."""
    stmt = (
        select(AuditLog)
        .where(AuditLog.entity_type == entity_type)
        .where(AuditLog.entity_id == entity_id)
        .order_by(AuditLog.created_at, AuditLog.id)
    )
    return list(db.scalars(stmt))
