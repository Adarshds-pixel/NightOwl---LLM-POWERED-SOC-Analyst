"""POST /incidents/{id}/chat -- incident-scoped chat (Day 11).

Persists the user's message, generates a grounded reply via
rag/chat_service.py's retrieve->answer pipeline (retrieval scoped to the
incident, same source-attribution shape as Day 9's explain endpoint),
persists the assistant's reply, and returns the assistant turn plus the
retrieved source chunks.

`GET /incidents/{id}/chat` (history) is Day 12 scope, not built here.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.errors import not_found
from app.db.session import get_db
from app.models.incident import Incident
from app.rag.chat_service import generate_chat_reply
from app.services.chat_service import add_message, list_messages

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


def _incident_to_dict(incident: Incident) -> dict:
    """Map the (currently sparse) Incident model to the loose dict shape
    rag/chat_service.generate_chat_reply expects -- same shape as
    routes_incidents.py's `_incident_to_dict` (duplicated here rather than
    imported/shared, matching this codebase's existing file-local-schema
    convention -- routes_incidents.py itself keeps its Pydantic models and
    this helper private rather than in a shared `schemas/` layer).
    """
    return {
        "description": incident.title,
        "severity": incident.severity,
        "host": incident.host,
        "technique_id": incident.mitre_technique_ids[0] if incident.mitre_technique_ids else None,
        "technique_ids": incident.mitre_technique_ids or [],
    }


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

    result = generate_chat_reply(_incident_to_dict(incident), history, payload.message)

    reply = add_message(db, incident_id, role="assistant", content=result.reply)

    return ChatMessageResponse(
        incident_id=incident_id,
        role=reply.role,
        content=reply.content,
        sources=[SourceChunk(**chunk) for chunk in result.chunks],
    )
