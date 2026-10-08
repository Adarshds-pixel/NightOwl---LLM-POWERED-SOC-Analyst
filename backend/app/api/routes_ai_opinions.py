"""GET /ai-opinions/{id} -- read-only poll endpoint for an LLM second
opinion on an ingest whose events had zero rule coverage (see
services/ai_opinion_service.py + models/ai_opinion.py). Fire-and-forget on
the write side: `POST /ingest` creates the row and schedules the LLM call
as a background task, this route just reports whatever state it's in.
"""

from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.ai_opinion import AiOpinion
from app.services.ai_opinion_service import fill_in_opinion

router = APIRouter()


class AiOpinionResponse(BaseModel):
    id: int
    filename: str
    created_at: datetime
    status: str
    assessment_label: str | None = None
    summary: str | None = None
    sample_event_ids: list[int]
    error: str | None = None
    # The parsed "## Limitations" section of `summary` -- always populated
    # alongside a successful summary, independent of assessment_label, so a
    # caller can render both without re-parsing free text (see
    # models/ai_opinion.py and rag/prompts.py's UNCOVERED_LIMITATIONS_HEADING).
    limitations: str | None = None
    # ATT&CK candidates sourced only from retrieved MITRE KB chunk metadata,
    # never from the LLM's own prose -- see
    # ai_opinion_service._attack_candidate_ids. None until the opinion
    # resolves; a real (possibly empty) list once it does.
    attack_candidate_ids: list[str] | None = None


def _to_response(opinion: AiOpinion) -> AiOpinionResponse:
    return AiOpinionResponse(
        id=opinion.id,
        filename=opinion.filename,
        created_at=opinion.created_at,
        status=opinion.status,
        assessment_label=opinion.assessment_label,
        summary=opinion.summary,
        sample_event_ids=opinion.sample_event_ids,
        error=opinion.error,
        limitations=opinion.limitations,
        attack_candidate_ids=opinion.attack_candidate_ids,
    )


@router.get("/ai-opinions/{opinion_id}", response_model=AiOpinionResponse)
def get_ai_opinion(opinion_id: int, db: Session = Depends(get_db)) -> AiOpinionResponse:
    opinion = db.get(AiOpinion, opinion_id)
    if opinion is None:
        raise HTTPException(status_code=404, detail=f"ai opinion {opinion_id} not found")
    return _to_response(opinion)


@router.post("/ai-opinions/{opinion_id}/retry", response_model=AiOpinionResponse, status_code=202)
def retry_ai_opinion(
    opinion_id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db)
) -> AiOpinionResponse:
    """Re-run a failed opinion (typically the free-tier rate limit) over the
    same stored sample events. Only a failed opinion can be retried; a pending
    or finished one is left alone. The retry sees the sampled events but not
    the original run's matched-rule context, which is not stored."""
    opinion = db.get(AiOpinion, opinion_id)
    if opinion is None:
        raise HTTPException(status_code=404, detail=f"ai opinion {opinion_id} not found")
    if opinion.status != "failed":
        raise HTTPException(status_code=409, detail="only a failed opinion can be retried")
    opinion.status = "pending"
    opinion.error = None
    db.commit()
    background_tasks.add_task(fill_in_opinion, opinion.id, opinion.filename, list(opinion.sample_event_ids))
    return _to_response(opinion)
