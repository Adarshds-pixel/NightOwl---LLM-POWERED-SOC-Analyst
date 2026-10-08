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

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.auth import session_actor
from app.core.config import settings
from app.core.errors import not_found
from app.db.session import get_db
from app.models.incident import Incident
from app.rag import cache
from app.rag.chat_service import generate_chat_reply
from app.services import audit_service
from app.services.chat_service import add_message, list_messages
from app.services.incident_service import build_incident_evidence, incident_cache_key

router = APIRouter()


class SourceChunk(BaseModel):
    chunk_id: str
    document: str
    metadata: dict
    score: float


# Bounds prompt size (and therefore cost/latency) per turn; generous for a
# real analyst question, far below anything that would blow the model context.
MAX_CHAT_MESSAGE_CHARS = 4000


class ChatMessageRequest(BaseModel):
    message: str = Field(min_length=1, max_length=MAX_CHAT_MESSAGE_CHARS)


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
    incident_id: int, payload: ChatMessageRequest, request: Request, db: Session = Depends(get_db)
) -> ChatMessageResponse:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise not_found("incident", incident_id)

    message = payload.message.strip()
    if not message:
        raise HTTPException(status_code=422, detail="message must not be blank")

    history = [{"role": m.role, "content": m.content} for m in list_messages(db, incident_id)]

    # The reply is generated BEFORE either turn is stored. Storing the
    # question first meant an LLM failure (503) left an unanswered user turn
    # in the history, which was then fed into every later prompt.
    cache_key = incident_cache_key(db, incident)
    result = cache.get_chat_reply(cache_key, message, history) if settings.response_cache_enabled else None
    if result is None:
        result = generate_chat_reply(build_incident_evidence(db, incident), history, message)
        if settings.response_cache_enabled:
            cache.set_chat_reply(cache_key, message, history, result)

    add_message(db, incident_id, role="user", content=message)
    reply = add_message(db, incident_id, role="assistant", content=result.reply)

    audit_service.record_event(
        db, entity_type="incident", entity_id=incident_id, action="chat", actor=session_actor(request)
    )

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
