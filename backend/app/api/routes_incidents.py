"""POST /incidents/{id}/explain -- runs rag/explain_service.py's retrieve ->
draft -> self-critique pipeline (Day 8) against a stored Incident and returns
the explanation, a separately-extracted recommended response, and the
retrieved source chunks + similarity scores (Day 9: source attribution, for
the frontend's Day 14 source-attribution UI).

Pair 1's incident grouping (`services/incident_service.py`, their Day 9 task)
doesn't exist yet, so `incidents` rows won't be populated by the real
detection pipeline until then -- this endpoint just reads whatever `Incident`
rows exist (e.g. inserted manually for testing), same "mocked until real"
posture as explain_service.py itself.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.incident import Incident
from app.rag.explain_service import generate_explanation
from app.rag.prompts import extract_recommended_response

router = APIRouter()


class SourceChunk(BaseModel):
    chunk_id: str
    document: str
    metadata: dict
    score: float


class ExplainResponse(BaseModel):
    incident_id: int
    explanation: str
    recommended_response: str
    sources: list[SourceChunk]


def _incident_to_dict(incident: Incident) -> dict:
    """Map the (currently sparse) Incident model to the loose dict shape
    explain_service.generate_explanation expects -- see its docstring on why
    that's a dict rather than the ORM model directly."""
    return {
        "description": incident.title,
        "severity": incident.severity,
        "technique_id": incident.mitre_technique_ids[0] if incident.mitre_technique_ids else None,
    }


@router.post("/incidents/{incident_id}/explain", response_model=ExplainResponse)
def explain_incident(incident_id: int, db: Session = Depends(get_db)) -> ExplainResponse:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"incident {incident_id} not found")

    result = generate_explanation(_incident_to_dict(incident))

    return ExplainResponse(
        incident_id=incident_id,
        explanation=result.explanation,
        recommended_response=extract_recommended_response(result.explanation),
        sources=[SourceChunk(**chunk) for chunk in result.chunks],
    )
