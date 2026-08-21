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

Day 13 (Pair 2, production hardening) adds:
  - a response cache in front of `explain_incident` (`rag/cache.py`), keyed
    on incident id, so a repeat explain call skips retrieval + the LLM call;
  - `PATCH /incidents/{id}/status` -- the only way `Incident.status` can
    change today outside incident_service.py's grouping logic, added so
    there's a status change for the new audit log to actually record;
  - `GET /incidents/{id}/audit` -- read access to the audit trail
    (`services/audit_service.py`) recorded for status changes and explain
    calls.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.errors import not_found
from app.db.session import get_db
from app.mitre.loader import load_mitre_techniques
from app.models.incident import Incident
from app.rag import cache
from app.rag.explain_service import generate_explanation
from app.rag.prompts import extract_recommended_response
from app.services import audit_service
from app.services.incident_service import count_incidents, get_incident_alerts_with_events, list_incidents

router = APIRouter()

ALLOWED_STATUSES = {"open", "investigating", "resolved", "closed"}


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
    count: int  # items in this page (== len(incidents))
    total: int  # Day 13: grand total matching the filters, across all pages
    limit: int
    offset: int


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


class IncidentStatusUpdateRequest(BaseModel):
    status: str
    actor: str | None = None


class IncidentStatusUpdateResponse(BaseModel):
    id: int
    status: str


class AuditLogEntry(BaseModel):
    id: int
    action: str
    actor: str
    details: dict | None
    created_at: datetime


class AuditLogResponse(BaseModel):
    incident_id: int
    events: list[AuditLogEntry]
    count: int


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

    result = cache.get_explanation(incident_id) if settings.response_cache_enabled else None
    if result is None:
        result = generate_explanation(_incident_to_dict(incident))
        if settings.response_cache_enabled:
            cache.set_explanation(incident_id, result)

    audit_service.record_event(db, entity_type="incident", entity_id=incident_id, action="explain")

    return ExplainResponse(
        incident_id=incident_id,
        explanation=result.explanation,
        recommended_response=extract_recommended_response(result.draft),
        sources=[SourceChunk(**chunk) for chunk in result.chunks],
    )


@router.patch("/incidents/{incident_id}/status", response_model=IncidentStatusUpdateResponse)
def update_incident_status(
    incident_id: int, payload: IncidentStatusUpdateRequest, db: Session = Depends(get_db)
) -> IncidentStatusUpdateResponse:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise not_found("incident", incident_id)

    if payload.status not in ALLOWED_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"invalid status '{payload.status}', must be one of {sorted(ALLOWED_STATUSES)}",
        )

    old_status = incident.status
    incident.status = payload.status
    db.commit()
    db.refresh(incident)

    audit_service.record_event(
        db,
        entity_type="incident",
        entity_id=incident_id,
        action="status_change",
        actor=payload.actor,
        details={"from": old_status, "to": payload.status},
    )

    return IncidentStatusUpdateResponse(id=incident.id, status=incident.status)


@router.get("/incidents/{incident_id}/audit", response_model=AuditLogResponse)
def get_incident_audit_log(incident_id: int, db: Session = Depends(get_db)) -> AuditLogResponse:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise not_found("incident", incident_id)

    events = audit_service.list_events(db, entity_type="incident", entity_id=incident_id)

    return AuditLogResponse(
        incident_id=incident_id,
        events=[
            AuditLogEntry(id=e.id, action=e.action, actor=e.actor, details=e.details, created_at=e.created_at)
            for e in events
        ],
        count=len(events),
    )


@router.get("/incidents", response_model=IncidentListResponse)
def get_incidents(
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> IncidentListResponse:
    incidents = list_incidents(
        db,
        severity=severity,
        status=status,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        offset=offset,
    )
    total = count_incidents(db, severity=severity, status=status, start_date=start_date, end_date=end_date)
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
        total=total,
        limit=limit,
        offset=offset,
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
