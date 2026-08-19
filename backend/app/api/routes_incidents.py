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

Day 12 (Pair 1) adds the two read endpoints incident grouping was always
meant to feed: `GET /incidents` (filtered list) and `GET /incidents/{id}`
(full detail -- alerts, their events, and resolved MITRE technique info).
"""

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.errors import not_found
from app.db.session import get_db
from app.mitre.loader import load_mitre_techniques
from app.models.incident import Incident
from app.rag.explain_service import generate_explanation
from app.rag.prompts import extract_recommended_response
from app.services.incident_service import get_incident_alerts_with_events, list_incidents

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


class IncidentSummary(BaseModel):
    id: int
    title: str
    status: str
    severity: str
    host: str
    mitre_technique_ids: list[str]
    created_at: datetime


class IncidentListResponse(BaseModel):
    incidents: list[IncidentSummary]
    count: int


class TechniqueInfo(BaseModel):
    id: str
    name: str
    tactics: list[str]


class EventInfo(BaseModel):
    id: int
    host: str
    timestamp: datetime
    event_id: int
    process: str | None
    command_line: str | None
    user: str | None


class AlertInfo(BaseModel):
    id: int
    rule_id: str
    matched_at: datetime
    severity: str
    event: EventInfo


class IncidentDetailResponse(BaseModel):
    id: int
    title: str
    status: str
    severity: str
    host: str
    created_at: datetime
    mitre_technique_ids: list[str]
    techniques: list[TechniqueInfo]
    alerts: list[AlertInfo]


def _incident_to_dict(incident: Incident) -> dict:
    """Map the (currently sparse) Incident model to the loose dict shape
    explain_service.generate_explanation expects -- see its docstring on why
    that's a dict rather than the ORM model directly.

    `technique_id` (singular) stays the *first* technique -- it's what
    explain_service uses to filter retrieval, which only supports one
    technique_id. `technique_ids` carries the full list so the LLM prompt
    context (format_incident_context renders every dict key) still shows
    every technique on incidents that grouped alerts for more than one.
    """
    return {
        "description": incident.title,
        "severity": incident.severity,
        "host": incident.host,
        "technique_id": incident.mitre_technique_ids[0] if incident.mitre_technique_ids else None,
        "technique_ids": incident.mitre_technique_ids or [],
    }


@router.post("/incidents/{incident_id}/explain", response_model=ExplainResponse)
def explain_incident(incident_id: int, db: Session = Depends(get_db)) -> ExplainResponse:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise not_found("incident", incident_id)

    result = generate_explanation(_incident_to_dict(incident))

    return ExplainResponse(
        incident_id=incident_id,
        explanation=result.explanation,
        recommended_response=extract_recommended_response(result.draft),
        sources=[SourceChunk(**chunk) for chunk in result.chunks],
    )


@router.get("/incidents", response_model=IncidentListResponse)
def get_incidents(
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    db: Session = Depends(get_db),
) -> IncidentListResponse:
    incidents = list_incidents(db, severity=severity, status=status, start_date=start_date, end_date=end_date)
    return IncidentListResponse(
        incidents=[
            IncidentSummary(
                id=incident.id,
                title=incident.title,
                status=incident.status,
                severity=incident.severity,
                host=incident.host,
                mitre_technique_ids=incident.mitre_technique_ids or [],
                created_at=incident.created_at,
            )
            for incident in incidents
        ],
        count=len(incidents),
    )


def _resolve_techniques(technique_ids: list[str]) -> list[TechniqueInfo]:
    """Looks up each of an incident's technique ids in the loaded MITRE
    dataset (same lookup `routes_mitre.py`'s catalog endpoint uses) --
    silently skips any id the dataset doesn't recognize rather than
    raising, matching mitre/validator.py's warn-only posture on bad tags.
    """
    catalog = load_mitre_techniques()
    techniques = []
    for technique_id in technique_ids:
        technique = catalog.get(technique_id)
        if technique is not None:
            techniques.append(TechniqueInfo(id=technique["id"], name=technique["name"], tactics=technique["tactics"]))
    return techniques


@router.get("/incidents/{incident_id}", response_model=IncidentDetailResponse)
def get_incident_detail(incident_id: int, db: Session = Depends(get_db)) -> IncidentDetailResponse:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise not_found("incident", incident_id)

    alerts = [
        AlertInfo(
            id=alert.id,
            rule_id=alert.rule_id,
            matched_at=alert.matched_at,
            severity=alert.severity,
            event=EventInfo(
                id=event.id,
                host=event.host,
                timestamp=event.timestamp,
                event_id=event.event_id,
                process=event.process,
                command_line=event.command_line,
                user=event.user,
            ),
        )
        for alert, event in get_incident_alerts_with_events(db, incident_id)
    ]

    return IncidentDetailResponse(
        id=incident.id,
        title=incident.title,
        status=incident.status,
        severity=incident.severity,
        host=incident.host,
        created_at=incident.created_at,
        mitre_technique_ids=incident.mitre_technique_ids or [],
        techniques=_resolve_techniques(incident.mitre_technique_ids or []),
        alerts=alerts,
    )
