"""POST /incidents/{id}/chat -- incident-scoped chat (Day 11).

Persists the user's message, generates a grounded reply via
rag/chat_service.py's retrieve->answer pipeline (retrieval scoped to the
incident, same source-attribution shape as Day 9's explain endpoint),
persists the assistant's reply, and returns the assistant turn plus the
retrieved source chunks.

`GET /incidents/{id}/chat` (history, Day 12) is a thin read wrapping the
same `list_messages` the POST handler already uses to build conversation
history.

Day 13 (Pair 2, production hardening) adds a response cache in front of the
POST handler (`rag/cache.py`), keyed on incident id + message, so a repeat
question skips retrieval + the LLM call, and records an audit log event
(`services/audit_service.py`) for every chat call.
"""

from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.errors import not_found
from app.db.session import get_db
from app.models.incident import Incident
from app.rag import cache
from app.rag.chat_service import generate_chat_reply
from app.services import audit_service
from app.services.chat_service import add_message, list_messages
from app.services.incident_service import build_incident_evidence

router = APIRouter()


class SourceChunk(BaseModel):
    chunk_id: str
    document: str
    metadata: dict
    score: float


class ChatMessageRequest(BaseModel):
    message: str


class ChatMessageResponse(BaseModel):
    incident_id: int
    role: str
    content: str
    sources: list[SourceChunk]


class ChatHistoryMessage(BaseModel):
    id: int
    role: str
    content: str
    created_at: datetime


class ChatHistoryResponse(BaseModel):
    incident_id: int
    messages: list[ChatHistoryMessage]
    count: int


@router.post("/incidents/{incident_id}/chat", response_model=ChatMessageResponse)
def chat_with_incident(
    incident_id: int, payload: ChatMessageRequest, db: Session = Depends(get_db)
) -> ChatMessageResponse:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise not_found("incident", incident_id)

    # Snapshot prior turns before persisting the new one, so it doesn't leak
    # into its own conversation-history context.
    history = [{"role": m.role, "content": m.content} for m in list_messages(db, incident_id)]

    add_message(db, incident_id, role="user", content=payload.message)

    result = cache.get_chat_reply(incident_id, payload.message, history) if settings.response_cache_enabled else None
    if result is None:
        result = generate_chat_reply(build_incident_evidence(db, incident), history, payload.message)
        if settings.response_cache_enabled:
            cache.set_chat_reply(incident_id, payload.message, history, result)

    reply = add_message(db, incident_id, role="assistant", content=result.reply)

    audit_service.record_event(db, entity_type="incident", entity_id=incident_id, action="chat")

    return ChatMessageResponse(
        incident_id=incident_id,
        role=reply.role,
        content=reply.content,
        sources=[SourceChunk(**chunk) for chunk in result.chunks],
    )


@router.get("/incidents/{incident_id}/chat", response_model=ChatHistoryResponse)
def get_chat_history(incident_id: int, db: Session = Depends(get_db)) -> ChatHistoryResponse:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise not_found("incident", incident_id)

    messages = list_messages(db, incident_id)

    return ChatHistoryResponse(
        incident_id=incident_id,
        messages=[
            ChatHistoryMessage(id=m.id, role=m.role, content=m.content, created_at=m.created_at)
            for m in messages
        ],
        count=len(messages),
    )
