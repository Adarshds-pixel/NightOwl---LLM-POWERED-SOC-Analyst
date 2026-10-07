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

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Request, UploadFile
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.detection.rule_loader import get_loaded_rules
from app.ingestion.evtx_reader import EvtxReadError, read_records_as_dicts
from app.ingestion.normalizer import EventNormalizationError, normalize_event
from app.services.ai_opinion_service import (
    REASON_NAMED_PIPE,
    REASON_SERVICE_INSTALL,
    REASON_UNCOVERED,
    create_pending_opinion,
    fill_in_opinion,
)
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


class EventIdCoverageGroup(BaseModel):
    channel: str | None
    event_id: int
    count: int
    covered: bool


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
    covered_events: int
    uncovered_events: int
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


@router.post("/ingest", response_model=IngestResponse, dependencies=[Depends(check_upload_size_limit)])
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
    # received, so this avoids reading anything just to measure it.
    if file.size is not None and file.size > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"file too large: {file.size} bytes exceeds the {MAX_UPLOAD_BYTES}-byte limit",
        )

    # Note on what this route can and can't protect against: Starlette's
    # multipart parser (FastAPI's `File(...)` dependency) has already fully
    # received and spooled the entire upload to a SpooledTemporaryFile
    # before this route function body even runs.
    #
    # APPLICATION-LEVEL FILE LIMIT: What this code *can* control is what
    # happens after spooling. We enforce MAX_UPLOAD_BYTES as chunks are
    # read below.
    #
    # PRE-RECEIVE NETWORK REQUEST LIMIT: The `check_upload_size_limit`
    # dependency provides early rejection based on Content-Length. However,
    # if Content-Length is omitted or forged, Starlette will still spool
    # the request. Because there is no hook in FastAPI/Starlette to cap
    # size *during* multipart parsing without a custom parser, production
    # deployments MUST enforce an upstream request-size limit (e.g., via
    # a proxy, load balancer, or ingress) before the application receives
    # an unbounded multipart request. Do not rely solely on route-level
    # validation to prevent disk exhaustion.
    #
    # read_records_as_dicts() requires a real file on disk (python-
    # evtx needs random-access seeking, confirmed via evtx_reader.py --
    # in-memory bytes/a stream won't do), so the already-spooled upload
    # still has to become a second on-disk file for the parser to read.
    # The previous version of this code read the *entire* spooled upload
    # into one contiguous Python `bytes` object first (`file.file.read()`)
    # and only then wrote that to the new temp file -- a full, avoidable
    # third in-memory copy of the whole upload with no purpose beyond
    # staging. Copying directly from the already-spooled file object to the
    # new temp file in bounded chunks avoids ever holding the full upload
    # as one Python object, and lets the size limit be enforced as bytes
    # are copied rather than only after a full second copy already exists.
    _COPY_CHUNK_BYTES = 1024 * 1024  # 1MB

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
        ai_opinion_id: int | None = None
        # Advisory second opinion, from two independent triggers:
        #   1. Some events had no rule that could even evaluate them --
        #      regardless of whether OTHER events in the same file matched a
        #      real rule. A real detection explains only the events it
        #      matched; it says nothing about the rest of the file. Proven
        #      live against a real capture: 2 rule matches alongside 1,531
        #      uncovered events used to suppress this opinion entirely,
        #      leaving those 1,531 events with zero analysis. When
        #      `matched_rule_titles` is non-empty, it's passed into the
        #      prompt as known context (see fill_in_opinion) so the opinion
        #      stays scoped to the *remaining* uncovered slice rather than
        #      re-litigating what a rule already caught -- advisory,
        #      additive, never a competing verdict.
        #   2. A narrow, verified advisory pattern was flagged (see
        #      advisory_patterns.py) -- independent of coverage/matches,
        #      since the pattern (e.g. a \lsass/\srvsvc named-pipe connect,
        #      or a Security 4697 service install whose ServiceType the one
        #      loaded 4697 rule doesn't evaluate) isn't represented as an
        #      Alert anywhere else in the file and still deserves a second
        #      look even if other, unrelated activity in the same file
        #      already matched a real rule -- "covered by a rule's
        #      logsource" is not the same claim as "this event's content
        #      was actually judged."
        # Advisory-pattern events go FIRST: the opinion only ever sees the
        # first MAX_SAMPLE_EVENTS ids, and with uncovered ids first any file
        # with 5+ uncovered events silently dropped the very 4697 / named-pipe
        # event that triggered the advisory.
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
            background_tasks.add_task(
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
            uncovered_events=outcome.uncovered_events,
            uncovered_breakdown=[
                UncoveredEventGroup(channel=g.channel, event_id=g.event_id, count=g.count)
                for g in outcome.uncovered_breakdown
            ],
            ai_opinion_id=ai_opinion_id,
            channels=outcome.channels,
            providers=outcome.providers,
            event_id_breakdown=[
                EventIdCoverageGroup(channel=g.channel, event_id=g.event_id, count=g.count, covered=g.covered)
                for g in outcome.event_id_breakdown
            ],
            ml_anomalies=outcome.ml_anomalies,
            ml_anomaly_titles=outcome.ml_anomaly_titles,
            ml_mode=settings.ml_mode,
        )
    finally:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink()
