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
fatal.

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
from app.detection.engine import evaluate_event
from app.detection.rule_loader import get_loaded_rules
from app.ingestion.evtx_reader import EvtxReadError, read_records_as_dicts
from app.ingestion.normalizer import EventNormalizationError, normalize_event
from app.services.detection_service import save_alerts
from app.services.event_service import save_events
from app.services.incident_service import find_or_create_incident

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

        records_read = 0
        skipped = 0
        normalized_events = []
        try:
            for record in read_records_as_dicts(tmp_path):
                records_read += 1
                try:
                    normalized_events.append(normalize_event(record))
                except EventNormalizationError as e:
                    logger.warning("skipping malformed record in %s: %s", filename, e)
                    skipped += 1
        except EvtxReadError as e:
            raise HTTPException(status_code=400, detail=f"failed to parse EVTX file: {e}") from e

        saved = save_events(db, normalized_events)

        rules = get_loaded_rules()
        matched_titles: list[str] = []
        rule_matches = 0
        alert_data = []
        incident_ids: list[int] = []
        matched_at = datetime.now(timezone.utc)
        for event_row, normalized_event in zip(saved, normalized_events, strict=True):
            for match in evaluate_event(normalized_event, rules):
                rule_matches += 1
                if match.title not in matched_titles:
                    matched_titles.append(match.title)
                incident = find_or_create_incident(db, normalized_event.host, matched_at, match)
                if incident.id not in incident_ids:
                    incident_ids.append(incident.id)
                alert_data.append((event_row.id, match, matched_at, incident.id))

        alerts = save_alerts(db, alert_data)

        logger.info(
            "ingest %s: %d records read, %d events ingested, %d skipped, %d rule matches, "
            "%d alerts created, %d incidents involved",
            filename, records_read, len(saved), skipped, rule_matches, len(alerts), len(incident_ids),
        )
        return IngestResponse(
            filename=filename,
            records_read=records_read,
            events_ingested=len(saved),
            events_skipped=skipped,
            rule_matches=rule_matches,
            matched_rule_titles=matched_titles,
            alerts_created=len(alerts),
            incident_ids=incident_ids,
        )
    finally:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink()
