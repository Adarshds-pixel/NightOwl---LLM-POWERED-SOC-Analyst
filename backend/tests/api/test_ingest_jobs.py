"""POST /ingest/async + GET /ingest/jobs/{id}: uploads processed in the
background so a large file cannot hit a browser timeout."""

from pathlib import Path

import pytest

from app.models.event import Event
from app.services import ingest_jobs

SYSMON_DEMO_PATH = Path(__file__).resolve().parents[2] / "sample_logs" / "sysmon_demo.evtx"


@pytest.fixture(autouse=True)
def _fresh_jobs(api_client, monkeypatch):
    _client, SessionLocal = api_client
    # The job thread opens its own session; point it at the test database.
    monkeypatch.setattr("app.api.routes_ingest.SessionLocal", SessionLocal)
    ingest_jobs.clear_jobs()
    yield
    ingest_jobs.clear_jobs()


def test_async_upload_returns_a_job_and_the_same_result_as_the_sync_route(api_client):
    client, SessionLocal = api_client
    with open(SYSMON_DEMO_PATH, "rb") as f:
        accepted = client.post("/ingest/async", files={"file": ("sysmon_demo.evtx", f, "application/octet-stream")})
    assert accepted.status_code == 202
    job_id = accepted.json()["job_id"]
    assert accepted.json()["filename"] == "sysmon_demo.evtx"

    status = client.get(f"/ingest/jobs/{job_id}").json()
    assert status["status"] == "done"
    assert status["records_read"] == 4
    assert status["result"]["events_ingested"] == 4
    assert status["result"]["covered_events"] == 4
    assert status["error"] is None
    with SessionLocal() as db:
        assert db.query(Event).count() == 4


def test_async_upload_of_an_unreadable_file_reports_a_failed_job(api_client):
    client, _SessionLocal = api_client
    accepted = client.post("/ingest/async", files={"file": ("broken.evtx", b"not an evtx file", "application/octet-stream")})
    assert accepted.status_code == 202

    status = client.get(f"/ingest/jobs/{accepted.json()['job_id']}").json()
    assert status["status"] == "failed"
    assert status["error_status"] == 400
    assert "failed to parse EVTX" in status["error"]
    assert status["result"] is None


def test_async_upload_rejects_a_wrong_extension_before_creating_a_job(api_client):
    client, _SessionLocal = api_client
    response = client.post("/ingest/async", files={"file": ("notes.txt", b"hello", "text/plain")})
    assert response.status_code == 400


def test_unknown_job_id_is_a_404(api_client):
    client, _SessionLocal = api_client
    assert client.get("/ingest/jobs/doesnotexist").status_code == 404


def test_async_route_has_the_same_size_limits_as_the_sync_route(api_client, monkeypatch):
    client, _SessionLocal = api_client
    monkeypatch.setattr("app.api.routes_ingest.MAX_UPLOAD_BYTES", 10)
    # Honest oversized Content-Length: rejected before the body is processed.
    declared = client.post(
        "/ingest/async",
        files={"file": ("small.evtx", b"x", "application/octet-stream")},
        headers={"Content-Length": str(10 + 1024 * 1024 + 1)},
    )
    assert declared.status_code == 413
    # Forged small Content-Length with a real oversized body: caught at staging.
    forged = client.post(
        "/ingest/async",
        files={"file": ("big.evtx", b"x" * 100, "application/octet-stream")},
    )
    assert forged.status_code == 413
    assert ingest_jobs._jobs == {}


def test_upload_guard_covers_the_async_route():
    from app.core.upload_guard import INGEST_PATHS

    assert {"/ingest", "/ingest/async"} <= INGEST_PATHS
