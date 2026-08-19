"""Incident chat persistence: `chat_messages` rows for one incident's
conversation (Day 11). Mirrors incident_service.py's layering -- the RAG
retrieve+prompt+LLM orchestration lives in rag/chat_service.py; this file
only owns reading/writing ChatMessage rows.
"""

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.chat_message import ChatMessage

logger = logging.getLogger(__name__)


def list_messages(db: Session, incident_id: int) -> list[ChatMessage]:
    """An incident's chat history, oldest first."""
    stmt = (
        select(ChatMessage)
        .where(ChatMessage.incident_id == incident_id)
        .order_by(ChatMessage.created_at)
    )
    return list(db.scalars(stmt))


def add_message(db: Session, incident_id: int, role: str, content: str) -> ChatMessage:
    """Persist one chat turn. Commits immediately -- unlike
    incident_service.find_or_create_incident (which leaves the transaction
    boundary to a batch caller), each call here is already its own complete
    unit of work, same posture as event_service.ingest_events/
    detection_service's batch-persist functions.
    """
    message = ChatMessage(
        incident_id=incident_id,
        role=role,
        content=content,
        created_at=datetime.now(timezone.utc),
    )
    db.add(message)
    db.commit()
    db.refresh(message)
    logger.info("persisted %s chat message for incident %d", role, incident_id)
    return message
