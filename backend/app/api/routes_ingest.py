"""POST /ingest -- accepts an EVTX upload, runs it through the read ->
normalize -> persist pipeline, and reports counts (Vol1 Sec3.4: this router
only orchestrates calls into ingestion/ and services/, it doesn't
re-implement their logic).

Defined as a sync `def` route (not `async def`) deliberately: every step
here is blocking I/O (temp-file write, python-evtx parsing, DB commit), and
FastAPI/Starlette automatically runs sync path operations in a worker
thread pool, so this gets thread-pool offloading for free without manual
run_in_threadpool calls.

Three named failure modes (Day 6 commit: "robust error handling"), checked
in this order, each returning 400 with a distinct `detail` message:
  1. wrong-format -- filename extension isn't .evtx
  2. empty        -- uploaded file has zero bytes
  3. malformed    -- correct extension, non-empty, but python-evtx can't
                      parse it (EvtxReadError from evtx_reader.py)

Individual malformed *records* inside an otherwise-valid file
(EventNormalizationError) are skipped and counted, not treated as a whole-
upload failure -- one corrupt/truncated record in a large real-world log
shouldn't block ingesting the rest of an otherwise-good batch, matching
normalizer.py's existing policy that narrow record-level problems aren't
fatal. The actual normalize -> persist -> detect -> group pipeline lives in
`services/ingest_service.py` (`ingest_records`), shared with the live-replay
service so a replayed scenario runs the identical code path a real upload
does; this route's own job is the file-format checks and EVTX parsing that
only apply to a browser upload.

Day 7 adds detection: every normalized event is evaluated against the
loaded Sigma rules (detection/rule_loader.py + detection/engine.py) before
being persisted. Day 8 persists each match as an `alerts` row
(models/alert.py, services/detection_service.py), keyed off the just-saved
Event row's DB id -- not the raw Sysmon/Windows Event ID on the
normalized event, which is a different number. Day 9 additionally groups
each match's alert into an incident (services/incident_service.py, same
host + a 1-hour window reuses the most recent open incident) before the
alert is persisted, so the alert's `incident_id` FK is set on creation
rather than backfilled later.
"""

import logging
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.detection.rule_loader import get_loaded_rules
from app.ingestion.evtx_reader import EvtxReadError, read_records_as_dicts
from app.services.ingest_service import ingest_records

logger = logging.getLogger(__name__)

router = APIRouter()

ALLOWED_EXTENSION = ".evtx"


class IngestResponse(BaseModel):
    filename: str
    records_read: int
    events_ingested: int
    events_skipped: int
    rule_matches: int
    matched_rule_titles: list[str]
    alerts_created: int
    incident_ids: list[int]


@router.post("/ingest", response_model=IngestResponse)
def ingest_evtx(file: UploadFile = File(...), db: Session = Depends(get_db)) -> IngestResponse:
    filename = file.filename or ""
    if not filename.lower().endswith(ALLOWED_EXTENSION):
        raise HTTPException(
            status_code=400,
            detail=f"unsupported file type: expected '{ALLOWED_EXTENSION}', got '{filename or '<no filename>'}'",
        )

    content = file.file.read()
    if not content:
        raise HTTPException(status_code=400, detail="uploaded file is empty")

    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=ALLOWED_EXTENSION, delete=False) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        try:
            records = list(read_records_as_dicts(tmp_path))
        except EvtxReadError as e:
            raise HTTPException(status_code=400, detail=f"failed to parse EVTX file: {e}") from e

        outcome = ingest_records(
            db,
            records,
            rules=get_loaded_rules(),
            matched_at=datetime.now(timezone.utc),
        )

        logger.info(
            "ingest %s: %d records read, %d events ingested, %d skipped, %d rule matches, "
            "%d alerts created, %d incidents involved",
            filename,
            outcome.records_read,
            outcome.events_ingested,
            outcome.events_skipped,
            outcome.rule_matches,
            outcome.alerts_created,
            len(outcome.incident_ids),
        )
        return IngestResponse(
            filename=filename,
            records_read=outcome.records_read,
            events_ingested=outcome.events_ingested,
            events_skipped=outcome.events_skipped,
            rule_matches=outcome.rule_matches,
            matched_rule_titles=outcome.matched_rule_titles,
            alerts_created=outcome.alerts_created,
            incident_ids=outcome.incident_ids,
        )
    finally:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink()
