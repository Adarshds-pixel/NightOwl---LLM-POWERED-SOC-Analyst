"""POST /ingest -- accepts an EVTX upload, runs it through the read ->
normalize -> persist pipeline, and reports counts (Vol1 Sec3.4: this router
only orchestrates calls into ingestion/ and services/, it doesn't
re-implement their logic).

Defined as a sync `def` route (not `async def`) deliberately: every step
here is blocking I/O (temp-file write, python-evtx parsing, DB commit), and
FastAPI/Starlette automatically runs sync path operations in a worker
thread pool, so this gets thread-pool offloading for free without manual
run_in_threadpool calls.

Four named failure modes (Day 6 commit: "robust error handling"; the 4th
added for demo-day robustness -- a panel handing over an unexpectedly huge
file should get a clear, fast rejection, not python-evtx grinding through
it with no feedback for minutes), checked in this order:
  1. wrong-format -- filename extension isn't .evtx (400)
  2. empty        -- uploaded file has zero bytes (400)
  3. too-large    -- exceeds MAX_UPLOAD_BYTES (413)
  4. malformed    -- correct extension, right size, but python-evtx can't
                      parse it (EvtxReadError from evtx_reader.py) (400)

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

`matched_at` is intentionally NOT "now": it is derived from each record's own
event timestamp (`ingest_records(matched_at=None)`), the same behavior the
former live-replay path used. Using wall-clock upload time here used to mean
uploading several distinct EVTX fixtures back-to-back in one testing session
(same host, all within the ~1 hour grouping window) silently merged them into
one incident, because "close together" was measured by when you clicked
upload rather than by when the activity actually happened. Grouping now
reflects the file's own history, so two unrelated captures only merge if the
activity they recorded genuinely happened close together.
"""

import logging
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.detection.rule_loader import get_loaded_rules
from app.ingestion.evtx_reader import EvtxReadError, read_records_as_dicts
from app.ingestion.normalizer import EventNormalizationError, normalize_event
from app.services.ai_opinion_service import create_pending_opinion, fill_in_opinion
from app.services.ingest_service import ingest_records

logger = logging.getLogger(__name__)

router = APIRouter()

ALLOWED_EXTENSION = ".evtx"
# 100MB -- comfortably above every real-world sample seen so far (the
# largest, a 10.5MB capture, already takes ~234s end to end; python-evtx
# parsing time scales with file size, so this is a backstop against a
# pathologically large upload hanging a live demo for many minutes with no
# feedback, not a realistic ceiling on a genuine single-host EVTX export).
MAX_UPLOAD_BYTES = 100 * 1024 * 1024


class UncoveredEventGroup(BaseModel):
    channel: str | None
    event_id: int
    count: int


class IngestResponse(BaseModel):
    filename: str
    records_read: int
    events_ingested: int
    events_skipped: int
    rule_matches: int
    matched_rule_titles: list[str]
    alerts_created: int
    incident_ids: list[int]
    # Coverage honesty (see detection/engine.py's covered_event_ids): an
    # event is "covered" when at least one loaded rule's declared channel +
    # category could ever evaluate it, regardless of whether it matched.
    # `rule_matches == 0` alone never distinguishes "scanned and clean"
    # from "no loaded rule could look at this event's channel/type at all"
    # -- these three fields make that distinction explicit instead of
    # letting the frontend (or a demo audience) assume the former.
    covered_events: int
    uncovered_events: int
    uncovered_breakdown: list[UncoveredEventGroup]
    # Non-null only when this ingest had zero rule matches AND at least one
    # uncovered event -- see the trigger condition below. Advisory only:
    # never conflate with alerts_created/incident_ids, and never block on
    # it (the LLM call itself runs as a background task after this
    # response is already built). GET /ai-opinions/{id} to poll it.
    ai_opinion_id: int | None = None


@router.post("/ingest", response_model=IngestResponse)
def ingest_evtx(
    background_tasks: BackgroundTasks, file: UploadFile = File(...), db: Session = Depends(get_db)
) -> IngestResponse:
    filename = file.filename or ""
    if not filename.lower().endswith(ALLOWED_EXTENSION):
        raise HTTPException(
            status_code=400,
            detail=f"unsupported file type: expected '{ALLOWED_EXTENSION}', got '{filename or '<no filename>'}'",
        )

    # Fast path: Starlette already knows the size once the upload is fully
    # received, so this avoids our own .read() building a second in-memory
    # copy of a huge file just to measure it.
    if file.size is not None and file.size > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"file too large: {file.size} bytes exceeds the {MAX_UPLOAD_BYTES}-byte limit",
        )

    content = file.file.read()
    if not content:
        raise HTTPException(status_code=400, detail="uploaded file is empty")
    # Fallback for when Starlette didn't populate `file.size` (e.g. certain
    # multipart/test-client shapes) -- same limit, checked after the read
    # since there was no way to know sooner.
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"file too large: {len(content)} bytes exceeds the {MAX_UPLOAD_BYTES}-byte limit",
        )

    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=ALLOWED_EXTENSION, delete=False) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        try:
            records = list(read_records_as_dicts(tmp_path))
        except EvtxReadError as e:
            raise HTTPException(status_code=400, detail=f"failed to parse EVTX file: {e}") from e

        # `ingest_records(matched_at=None)` groups incidents by each record's
        # own event time and requires ascending order (see its docstring).
        # EVTX chunk order is usually close to chronological but is not
        # guaranteed, so this sorts explicitly rather than trusting file
        # order. A record that fails to normalize here sorts last -- it
        # doesn't matter where it lands, since ingest_records' own
        # normalization pass will skip it for real and count it.
        _DISTANT_FUTURE = datetime.max.replace(tzinfo=timezone.utc)

        def _timestamp_sort_key(record: dict) -> datetime:
            try:
                return normalize_event(record).timestamp
            except EventNormalizationError:
                return _DISTANT_FUTURE

        records.sort(key=_timestamp_sort_key)

        outcome = ingest_records(
            db,
            records,
            rules=get_loaded_rules(),
            matched_at=None,
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
        ai_opinion_id: int | None = None
        # Advisory second opinion only for a file NO rule fired on AND that
        # had events no rule could even evaluate -- a file with real
        # matches already has a real detection to look at, and a file
        # that's fully covered with no matches is genuinely, verifiably
        # clean. This is deliberately the narrow slice where an LLM opinion
        # adds something a rule-based verdict can't.
        if outcome.rule_matches == 0 and outcome.uncovered_events > 0:
            opinion = create_pending_opinion(db, filename, outcome.uncovered_event_ids)
            ai_opinion_id = opinion.id
            background_tasks.add_task(fill_in_opinion, opinion.id, filename, outcome.uncovered_event_ids)

        return IngestResponse(
            filename=filename,
            records_read=outcome.records_read,
            events_ingested=outcome.events_ingested,
            events_skipped=outcome.events_skipped,
            rule_matches=outcome.rule_matches,
            matched_rule_titles=outcome.matched_rule_titles,
            alerts_created=outcome.alerts_created,
            incident_ids=outcome.incident_ids,
            covered_events=outcome.covered_events,
            uncovered_events=outcome.uncovered_events,
            uncovered_breakdown=[
                UncoveredEventGroup(channel=g.channel, event_id=g.event_id, count=g.count)
                for g in outcome.uncovered_breakdown
            ],
            ai_opinion_id=ai_opinion_id,
        )
    finally:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink()
