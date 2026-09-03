"""POST /demo/reset -- wipes ingested demo data so a fresh run (either the
one-shot "Run demo" pipeline or a manual EVTX upload) starts from a clean
slate instead of piling more events/alerts/incidents onto whatever is
already there.

Gated behind `require_demo_mode` in addition to the usual `require_api_key`
-- this is destructive, and a deployment that is not meant to demo itself
(settings.demo_mode_enabled=False) should not expose it at all, not merely
rely on the shared API key being set.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.services import audit_service, demo_service

router = APIRouter()


def require_demo_mode() -> None:
    if not settings.demo_mode_enabled:
        raise HTTPException(status_code=403, detail="demo mode is disabled on this deployment")


class DemoResetResponse(BaseModel):
    deleted: dict[str, int]


@router.post("/demo/reset", response_model=DemoResetResponse)
def reset_demo(db: Session = Depends(get_db)) -> DemoResetResponse:
    deleted = demo_service.reset_demo_data(db)
    # Recorded after the delete commits, not before -- audit_log is one of
    # the tables being wiped, so a pre-reset entry would just be erased by
    # its own reset.
    audit_service.record_event(db, entity_type="demo", entity_id=0, action="reset", details=deleted)

    return DemoResetResponse(deleted=deleted)
