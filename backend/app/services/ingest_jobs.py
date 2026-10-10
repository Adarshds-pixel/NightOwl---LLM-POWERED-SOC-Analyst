"""In-memory registry of background upload jobs.

A big EVTX takes minutes to parse (python-evtx renders about 100 records per
second), longer than a browser is willing to wait on one HTTP request. The
console therefore uploads with `POST /ingest/async`, gets a job id back at once
and polls `GET /ingest/jobs/{id}` for progress and the final result.

Jobs live in this process's memory: they survive neither a restart nor a second
worker process. That is acceptable here -- a lost job only means the upload has
to be repeated (events already stored are skipped as duplicates) -- and it keeps
the feature free of a new table and migration. The backend runs a single
uvicorn worker (see docker-entrypoint.sh).
"""

import threading
import time
import uuid
from dataclasses import dataclass, field

JOB_TTL_SECONDS = 3600


@dataclass
class IngestJob:
    id: str
    filename: str
    # reading -> analysing -> done | failed
    status: str = "reading"
    records_read: int = 0
    records_total: int | None = None
    tmp_key: str | None = None
    # when the reading phase started, for the elapsed/ETA figures
    started_at: float = field(default_factory=time.time)
    result: dict | None = None
    error: str | None = None
    error_status: int | None = None
    created_at: float = field(default_factory=time.time)


_jobs: dict[str, IngestJob] = {}
_lock = threading.Lock()


def _prune(now: float) -> None:
    for job_id in [j.id for j in _jobs.values() if now - j.created_at > JOB_TTL_SECONDS]:
        del _jobs[job_id]


def create_job(filename: str) -> IngestJob:
    job = IngestJob(id=uuid.uuid4().hex, filename=filename)
    with _lock:
        _prune(time.time())
        _jobs[job.id] = job
    return job


def get_job(job_id: str) -> IngestJob | None:
    with _lock:
        return _jobs.get(job_id)


def clear_jobs() -> None:
    """Test helper."""
    with _lock:
        _jobs.clear()
