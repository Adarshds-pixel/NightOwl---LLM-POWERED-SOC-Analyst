"""Day 6 verification (Pair 1): POST /ingest accepts EVTX uploads, runs
the read -> normalize -> persist pipeline, and handles malformed/empty/
wrong-format files.
"""

from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.event import Event

SYSMON_DEMO_PATH = Path(__file__).resolve().parents[2] / "data" / "sample_logs" / "sysmon_demo.evtx"


def _client_and_sessionmaker():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    def _override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db
    client = TestClient(app)
    return client, TestingSessionLocal


def _system(event_id, computer="WORKSTATION01", system_time="2026-05-24T15:25:16.809914+00:00"):
    return {
        "EventID": event_id,
        "TimeCreated": {"@SystemTime": system_time},
        "Computer": computer,
    }


def _record(event_id, computer="WORKSTATION01"):
    return {"Event": {"System": _system(event_id, computer=computer), "EventData": {"Data": []}}}


def test_ingest_sysmon_demo_happy_path():
    client, SessionLocal = _client_and_sessionmaker()
    try:
        with open(SYSMON_DEMO_PATH, "rb") as f:
            response = client.post(
                "/ingest",
                files={"file": ("sysmon_demo.evtx", f, "application/octet-stream")},
            )
        assert response.status_code == 200
        assert response.json() == {
            "filename": "sysmon_demo.evtx",
            "records_read": 4,
            "events_ingested": 4,
            "events_skipped": 0,
            "rule_matches": 0,
            "matched_rule_titles": [],
            "alerts_created": 0,
            "incident_ids": [],
        }
        with SessionLocal() as db:
            assert db.query(Event).count() == 4
    finally:
        app.dependency_overrides.clear()


def test_ingest_rejects_wrong_extension():
    client, SessionLocal = _client_and_sessionmaker()
    try:
        response = client.post(
            "/ingest",
            files={"file": ("notlogs.txt", b"just some text", "text/plain")},
        )
        assert response.status_code == 400
        assert "unsupported file type" in response.json()["detail"]
        with SessionLocal() as db:
            assert db.query(Event).count() == 0
    finally:
        app.dependency_overrides.clear()


def test_ingest_rejects_empty_file():
    client, _ = _client_and_sessionmaker()
    try:
        response = client.post(
            "/ingest",
            files={"file": ("empty.evtx", b"", "application/octet-stream")},
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "uploaded file is empty"
    finally:
        app.dependency_overrides.clear()


def test_ingest_rejects_corrupted_evtx_bytes():
    client, _ = _client_and_sessionmaker()
    try:
        # Under ~40 bytes, python-evtx fails to even read the file header and
        # raises EvtxReadError; larger garbage blobs are read as a
        # zero-chunk/zero-record file instead of raising (see evtx_reader.py) --
        # this size is chosen specifically to exercise the EvtxReadError path.
        garbage = b"not a real evtx file, too short"
        response = client.post(
            "/ingest",
            files={"file": ("corrupt.evtx", garbage, "application/octet-stream")},
        )
        assert response.status_code == 400
        assert response.json()["detail"].startswith("failed to parse EVTX file")
    finally:
        app.dependency_overrides.clear()


def test_ingest_skips_malformed_records_and_ingests_the_rest(monkeypatch):
    client, SessionLocal = _client_and_sessionmaker()
    try:
        good_1 = _record("1")
        good_2 = _record("11")
        bad = _record("1")
        del bad["Event"]["System"]["EventID"]  # triggers EventNormalizationError

        monkeypatch.setattr(
            "app.api.routes_ingest.read_records_as_dicts",
            lambda path: iter([good_1, bad, good_2]),
        )

        response = client.post(
            "/ingest",
            files={"file": ("fake.evtx", b"content is irrelevant, reader is mocked", "application/octet-stream")},
        )
        assert response.status_code == 200
        assert response.json() == {
            "filename": "fake.evtx",
            "records_read": 3,
            "events_ingested": 2,
            "events_skipped": 1,
            "rule_matches": 0,
            "matched_rule_titles": [],
            "alerts_created": 0,
            "incident_ids": [],
        }
        with SessionLocal() as db:
            assert db.query(Event).count() == 2
    finally:
        app.dependency_overrides.clear()
