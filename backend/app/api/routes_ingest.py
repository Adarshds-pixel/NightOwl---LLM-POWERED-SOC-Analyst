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
import time
import threading
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Request, UploadFile
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import SessionLocal, get_db
from app.detection.rule_loader import get_loaded_rules
from app.ingestion import evtx_reader
from app.ingestion.evtx_reader import EvtxReadError, count_records, read_records_as_dicts
from app.ingestion.normalizer import EventNormalizationError, normalize_event
from app.services.ai_opinion_service import (
    REASON_NAMED_PIPE,
    REASON_SERVICE_INSTALL,
    REASON_UNCOVERED,
    create_pending_opinion,
    fill_in_opinion,
)
from app.services import ingest_jobs
from app.services.ingest_service import ingest_records

logger = logging.getLogger(__name__)

router = APIRouter()

ALLOWED_EXTENSION = ".evtx"
# 100MB -- comfortably above every real-world sample seen so far (the
# largest, a 10.5MB capture, already takes ~234s end to end; python-evtx
# parsing time scales with file size, so this is a backstop against a
# pathologically large upload hanging a live demo for many minutes with no
# feedback, not a realistic ceiling on a genuine single-host EVTX export).
#
# The value lives in settings.max_upload_bytes so the pre-body upload guard
# (core/upload_guard.py) and this route enforce the same number.
MAX_UPLOAD_BYTES = settings.max_upload_bytes


class UncoveredEventGroup(BaseModel):
    channel: str | None
    event_id: int
    count: int


class IngestNoticeModel(BaseModel):
    kind: str
    message: str
    count: int


class EventIdCoverageGroup(BaseModel):
    channel: str | None
    event_id: int
    count: int
    covered: bool
    # "checked" (a rule/detector evaluates it) | "routine" (everyday activity,
    # no rule needed) | "unchecked" (security-relevant, nothing evaluates it).
    kind: str = "unchecked"


class IngestResponse(BaseModel):
    filename: str
    records_read: int
    events_ingested: int
    events_skipped: int
    # Records that parsed and normalized fine but matched an event already
    # stored (same host/channel/EventRecordID -- Windows' own per-log
    # record identity, not something NightOwl invents) and so were never
    # inserted. Uploading the same EVTX file, or a re-export overlapping
    # an earlier one, twice reports these here instead of silently
    # doubling events_ingested and every KPI derived from it.
    duplicate_events_skipped: int
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
    # covered_events = CHECKED; routine_events = everyday activity that needs
    # no rule; uncovered_events = UNCHECKED only (the events worth a review).
    covered_events: int
    routine_events: int = 0
    uncovered_events: int
    # Events matching a narrow advisory pattern (named-pipe discovery, an
    # ordinary-service install): too noisy for a rule, worth a human look.
    advisory_hits: int = 0
    # Informational notes about the file (never alerts), e.g. a log clear.
    notices: list[IngestNoticeModel] = []
    uncovered_breakdown: list[UncoveredEventGroup]
    # Non-null only when this ingest had zero rule matches AND at least one
    # uncovered event -- see the trigger condition below. Advisory only:
    # never conflate with alerts_created/incident_ids, and never block on
    # it (the LLM call itself runs as a background task after this
    # response is already built). GET /ai-opinions/{id} to poll it.
    ai_opinion_id: int | None = None
    # Telemetry profiler: what's actually in this file, before/regardless
    # of alert count -- distinct raw Channel/Provider strings seen, and
    # every (channel, event_id) group with its coverage verdict (a
    # superset of uncovered_breakdown above, which stays for backward
    # compatibility with existing consumers of that narrower field).
    channels: list[str]
    providers: list[str]
    event_id_breakdown: list[EventIdCoverageGroup]
    # ML anomaly layer -- reported separately from rule detections, never
    # included in rule_matches / alerts_created / matched_rule_titles.
    ml_anomalies: int = 0
    ml_anomaly_titles: list[str] = []
    ml_mode: str = "advisory"


async def check_upload_size_limit(request: Request):
    """
    Early rejection based on Content-Length, if provided.
    This does NOT prevent an attacker from omitting or forging Content-Length
    to force multipart spooling, which is a known Starlette limitation.
    """
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            # We allow 1MB of overhead for multipart boundaries/headers
            # over the actual EVTX file limit.
            if int(content_length) > MAX_UPLOAD_BYTES + (1024 * 1024):
                raise HTTPException(
                    status_code=413,
                    detail=f"Request body too large: content-length exceeds the limit",
                )
        except ValueError:
            pass

    # Post-spooling application-level limit enforcement on all parts.
    # Starlette's multipart parser will have spooled the request by this point
    # (or will spool it when we await request.form()). We must ensure the total
    # received data doesn't exceed the limit, even if an attacker split it
    # across multiple files/fields or used chunked transfer to bypass Content-Length.
    form = await request.form()
    total_size = 0
    for key, value in form.multi_items():
        if hasattr(value, "size") and value.size is not None:
            total_size += value.size
        elif isinstance(value, str):
            total_size += len(value.encode("utf-8"))

    if total_size > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Request body too large: total size of all parts exceeds the limit",
        )


_COPY_CHUNK_BYTES = 1024 * 1024  # 1MB

# Uploads processed at once (settings.max_concurrent_ingests). A slot is taken
# before the file is staged and released when its processing ends, so a second
# upload during a long one is refused at once instead of competing for memory.
_ingest_slots = threading.BoundedSemaphore(max(1, settings.max_concurrent_ingests))
BUSY_DETAIL = "Another upload is still being processed -- try again when it finishes."


def _take_ingest_slot() -> None:
    if not _ingest_slots.acquire(blocking=False):
        raise HTTPException(status_code=409, detail=BUSY_DETAIL)


class IngestJobAccepted(BaseModel):
    job_id: str
    filename: str


class IngestJobStatus(BaseModel):
    job_id: str
    filename: str
    # reading -> analysing -> done | failed
    status: str
    records_read: int
    # total records in the file (None if unknown) and timing, so the console
    # can show "N of M records" and an ETA while reading
    records_total: int | None = None
    elapsed_seconds: float = 0.0
    eta_seconds: float | None = None
    result: IngestResponse | None = None
    error: str | None = None
    # HTTP status the synchronous route would have returned for a failure
    # (e.g. 400 for an unreadable file), so the console can word it the same way.
    error_status: int | None = None


def _stage_upload(file: UploadFile) -> Path:
    """Validates the upload and copies it to a temp .evtx file the parser can
    seek in. The caller owns (and must delete) the returned path.

    Note on what this can and can't protect against: Starlette has already
    fully received and spooled the upload before this runs, so the size limit
    here (and the early Content-Length check in `check_upload_size_limit`)
    stops oversized uploads from being processed, not from being received.
    Production deployments must also cap request size upstream (proxy or load
    balancer); core/upload_guard.py enforces the same limit before the body is
    read at all. The copy is chunked so the whole upload is never one Python
    object, and the limit is enforced as bytes are copied.
    """
    filename = file.filename or ""
    if not filename.lower().endswith(ALLOWED_EXTENSION):
        raise HTTPException(
            status_code=400,
            detail=f"unsupported file type: expected '{ALLOWED_EXTENSION}', got '{filename or '<no filename>'}'",
        )
    if file.size is not None and file.size > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"file too large: {file.size} bytes exceeds the {MAX_UPLOAD_BYTES}-byte limit",
        )

    tmp_path: Path | None = None
    try:
        total_bytes = 0
        with tempfile.NamedTemporaryFile(suffix=ALLOWED_EXTENSION, delete=False) as tmp:
            tmp_path = Path(tmp.name)
            while chunk := file.file.read(_COPY_CHUNK_BYTES):
                total_bytes += len(chunk)
                if total_bytes > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"file too large: exceeds the {MAX_UPLOAD_BYTES}-byte limit",
                    )
                tmp.write(chunk)
        if total_bytes == 0:
            raise HTTPException(status_code=400, detail="uploaded file is empty")
        return tmp_path
    except BaseException:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink()
        raise


def _read_sorted_records(tmp_path: Path, on_progress=None) -> list[dict]:
    try:
        records: list[dict] = []
        for record in read_records_as_dicts(tmp_path):
            records.append(record)
            if on_progress is not None and len(records) % 200 == 0:
                on_progress(len(records))
        if on_progress is not None:
            on_progress(len(records))
    except EvtxReadError as e:
        raise HTTPException(status_code=400, detail=f"failed to parse EVTX file: {e}") from e

    # `ingest_records(matched_at=None)` groups incidents by each record's own
    # event time and requires ascending order (see its docstring). EVTX chunk
    # order is usually close to chronological but is not guaranteed, so sort
    # explicitly. A record that fails to normalize sorts last; ingest_records'
    # own normalization pass will skip and count it.
    distant_future = datetime.max.replace(tzinfo=timezone.utc)

    def _timestamp_sort_key(record: dict) -> datetime:
        try:
            return normalize_event(record).timestamp
        except EventNormalizationError:
            return distant_future

    records.sort(key=_timestamp_sort_key)
    return records


def _process_records(db: Session, records: list[dict], filename: str, schedule) -> IngestResponse:
    """Detection, correlation, persistence and the advisory AI review for one
    already-read file. `schedule(fn, *args)` runs the AI task after the
    response is built (a FastAPI background task for the synchronous route, a
    thread for upload jobs)."""
    outcome = ingest_records(db, records, rules=get_loaded_rules(), matched_at=None)

    logger.info(
        "ingest %s: %d records read, %d events ingested, %d skipped, %d duplicates skipped, "
        "%d rule matches, %d alerts created, %d incidents involved",
        filename,
        outcome.records_read,
        outcome.events_ingested,
        outcome.events_skipped,
        outcome.duplicate_events_skipped,
        outcome.rule_matches,
        outcome.alerts_created,
        len(outcome.incident_ids),
    )

    # Advisory AI review, from two independent triggers:
    #   1. Security-relevant events that no rule or detector checks (everyday
    #      activity never triggers it -- see detection/coverage.py). A real
    #      detection explains only the events it matched, so this still runs
    #      when other events in the file matched; `matched_rule_titles` is
    #      passed to the prompt as known context so the review stays scoped to
    #      the remaining slice.
    #   2. A narrow advisory pattern (advisory_patterns.py): named-pipe
    #      discovery or an ordinary-service install, too noisy for a rule.
    # Advisory-pattern events go FIRST: the review only sees the first
    # MAX_SAMPLE_EVENTS ids, and with unchecked ids first a file with many of
    # them would silently drop the very event that triggered the advisory.
    ai_opinion_id: int | None = None
    sample_reasons: dict[int, str] = {}
    for event_id in outcome.named_pipe_discovery_event_ids:
        sample_reasons.setdefault(event_id, REASON_NAMED_PIPE)
    for event_id in outcome.service_installation_event_ids:
        sample_reasons.setdefault(event_id, REASON_SERVICE_INSTALL)
    advisory_sample_ids = list(sample_reasons)
    if outcome.uncovered_events > 0:
        for event_id in outcome.uncovered_event_ids:
            sample_reasons.setdefault(event_id, REASON_UNCOVERED)
        advisory_sample_ids = list(dict.fromkeys(advisory_sample_ids + outcome.uncovered_event_ids))
    if advisory_sample_ids:
        opinion = create_pending_opinion(db, filename, advisory_sample_ids)
        ai_opinion_id = opinion.id
        schedule(
            fill_in_opinion,
            opinion.id,
            filename,
            advisory_sample_ids,
            outcome.matched_rule_titles,
            outcome.uncovered_breakdown,
            sample_reasons,
            outcome.ml_anomaly_titles,
        )

    db.commit()

    return IngestResponse(
        filename=filename,
        records_read=outcome.records_read,
        events_ingested=outcome.events_ingested,
        events_skipped=outcome.events_skipped,
        duplicate_events_skipped=outcome.duplicate_events_skipped,
        rule_matches=outcome.rule_matches,
        matched_rule_titles=outcome.matched_rule_titles,
        alerts_created=outcome.alerts_created,
        incident_ids=outcome.incident_ids,
        covered_events=outcome.covered_events,
        routine_events=outcome.routine_events,
        notices=[IngestNoticeModel(kind=n.kind, message=n.message, count=n.count) for n in outcome.notices],
        advisory_hits=len(outcome.named_pipe_discovery_event_ids) + len(outcome.service_installation_event_ids),
        uncovered_events=outcome.uncovered_events,
        uncovered_breakdown=[
            UncoveredEventGroup(channel=g.channel, event_id=g.event_id, count=g.count)
            for g in outcome.uncovered_breakdown
        ],
        ai_opinion_id=ai_opinion_id,
        channels=outcome.channels,
        providers=outcome.providers,
        event_id_breakdown=[
            EventIdCoverageGroup(channel=g.channel, event_id=g.event_id, count=g.count, covered=g.covered, kind=g.kind)
            for g in outcome.event_id_breakdown
        ],
        ml_anomalies=outcome.ml_anomalies,
        ml_anomaly_titles=outcome.ml_anomaly_titles,
        ml_mode=settings.ml_mode,
    )


@router.post("/ingest", response_model=IngestResponse, dependencies=[Depends(check_upload_size_limit)])
def ingest_evtx(
    background_tasks: BackgroundTasks, file: UploadFile = File(...), db: Session = Depends(get_db)
) -> IngestResponse:
    """Synchronous upload: the response is the finished result. Fine for small
    files and for scripts; the console uses /ingest/async instead so a large
    file cannot hit a browser timeout."""
    filename = file.filename or ""
    _take_ingest_slot()
    try:
        tmp_path = _stage_upload(file)
        try:
            records = _read_sorted_records(tmp_path)
            return _process_records(db, records, filename, background_tasks.add_task)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()
    finally:
        _ingest_slots.release()


def _run_ingest_job(job_id: str, tmp_path: Path, filename: str) -> None:
    job = ingest_jobs.get_job(job_id)
    if job is None:
        if tmp_path.exists():
            tmp_path.unlink()
        _ingest_slots.release()
        return
    db = SessionLocal()

    def _start_thread(fn, *args) -> None:
        threading.Thread(target=fn, args=args, daemon=True).start()

    def _progress(count: int) -> None:
        job.records_read = count

    try:
        job.tmp_key = str(tmp_path)
        job.records_total = count_records(tmp_path)
        job.started_at = time.time()
        records = _read_sorted_records(tmp_path, _progress)
        job.status = "analysing"
        response = _process_records(db, records, filename, _start_thread)
        job.result = response.model_dump()
        job.status = "done"
    except HTTPException as e:
        db.rollback()
        job.error, job.error_status, job.status = str(e.detail), e.status_code, "failed"
    except Exception as e:  # noqa: BLE001 -- a background job must record, not raise
        logger.exception("ingest job %s failed", job_id)
        db.rollback()
        job.error, job.error_status, job.status = f"internal error while ingesting ({type(e).__name__})", 500, "failed"
    finally:
        db.close()
        if tmp_path.exists():
            tmp_path.unlink()
        _ingest_slots.release()


@router.post("/ingest/async", response_model=IngestJobAccepted, status_code=202, dependencies=[Depends(check_upload_size_limit)])
def ingest_evtx_async(background_tasks: BackgroundTasks, file: UploadFile = File(...)) -> IngestJobAccepted:
    """Upload now, process in the background: returns a job id immediately and
    `GET /ingest/jobs/{id}` reports progress and, when finished, the same
    payload `POST /ingest` returns."""
    filename = file.filename or ""
    _take_ingest_slot()
    try:
        tmp_path = _stage_upload(file)
        job = ingest_jobs.create_job(filename)
    except BaseException:
        _ingest_slots.release()
        raise
    # The job releases the slot when it finishes (see _run_ingest_job).
    background_tasks.add_task(_run_ingest_job, job.id, tmp_path, filename)
    return IngestJobAccepted(job_id=job.id, filename=filename)


@router.get("/ingest/jobs/{job_id}", response_model=IngestJobStatus)
def get_ingest_job(job_id: str) -> IngestJobStatus:
    job = ingest_jobs.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="upload job not found (it may have expired or the server restarted)")
    elapsed = time.time() - job.started_at
    # parallel readers publish how many records the worker processes have
    # rendered so far, which moves smoothly; the yielded count only jumps
    read = job.records_read
    if job.status == "reading" and job.tmp_key:
        read = max(read, evtx_reader.render_progress.get(job.tmp_key, 0))
    eta = None
    if job.status == "reading" and job.records_total and read >= 200 and elapsed > 1:
        eta = round(max(job.records_total - read, 0) * elapsed / read, 0)
    return IngestJobStatus(
        job_id=job.id,
        filename=job.filename,
        status=job.status,
        records_read=read,
        records_total=job.records_total,
        elapsed_seconds=round(elapsed, 1),
        eta_seconds=eta,
        result=IngestResponse(**job.result) if job.result is not None else None,
        error=job.error,
        error_status=job.error_status,
    )
