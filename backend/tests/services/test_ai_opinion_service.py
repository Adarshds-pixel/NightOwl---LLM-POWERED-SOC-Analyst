"""services/ai_opinion_service.py -- LLM second-opinion generation for
uncovered events. Mirrors test_chat_service.py's mocking style: patches
`retrieve`/`generate` at their app.services.ai_opinion_service import
location, no network or LLM call. Advisory-only boundary (never an
Alert/Incident, never blocks the caller) is the thing under test here --
retrieval/prompt-rendering correctness is rag/test_*.py's job.
"""

from datetime import datetime, timezone

from app.models.ai_opinion import AiOpinion
from app.models.event import Event
from app.rag.llm_client import LLMProviderError
from app.services import ai_opinion_service

SAMPLE_CHUNKS = [
    {
        "chunk_id": "T1003-mitre-0",
        "document": "Adversaries may attempt to dump credentials.",
        "metadata": {"source_type": "mitre_technique", "technique_id": "T1003"},
        "score": 0.7,
    }
]

# A playbook chunk can also carry a technique_id (ai/tools/build_kb.py), but
# it is guidance text, not a MITRE technique document -- must never populate
# attack_candidate_ids (see ai_opinion_service._attack_candidate_ids).
SAMPLE_PLAYBOOK_CHUNK = {
    "chunk_id": "T1003-playbook-0",
    "document": "Response steps for credential dumping.",
    "metadata": {"source_type": "playbook", "technique_id": "T1003"},
    "score": 0.65,
}


def _make_event(db, *, channel="Security", event_id=4624, process=None) -> Event:
    event = Event(
        host="DC1",
        timestamp=datetime(2026, 8, 30, 9, 0, 0, tzinfo=timezone.utc),
        event_id=event_id,
        channel=channel,
        process=process,
        command_line=None,
        user=None,
        raw_json={},
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def test_create_pending_opinion_inserts_pending_row(api_client):
    _client, SessionLocal = api_client
    with SessionLocal() as db:
        opinion = ai_opinion_service.create_pending_opinion(db, "mystery.evtx", sample_event_ids=[1, 2])

        assert opinion.id is not None
        assert opinion.status == "pending"
        assert opinion.filename == "mystery.evtx"
        assert opinion.sample_event_ids == [1, 2]
        assert opinion.assessment_label is None
        assert opinion.summary is None


def test_create_pending_opinion_caps_sample_event_ids(api_client):
    _client, SessionLocal = api_client
    with SessionLocal() as db:
        many_ids = list(range(1, 20))
        opinion = ai_opinion_service.create_pending_opinion(db, "big.evtx", sample_event_ids=many_ids)

        assert len(opinion.sample_event_ids) == ai_opinion_service.MAX_SAMPLE_EVENTS


def test_fill_in_opinion_success_updates_status_and_label(api_client, monkeypatch):
    _client, SessionLocal = api_client
    # fill_in_opinion opens its OWN fresh SessionLocal() (by design -- a
    # background task's request-scoped session may already be closed by
    # the time it runs). In production there's only one real database, so
    # the module-level SessionLocal it imports is correct as-is; in tests,
    # that name must be patched to the fixture's in-memory engine the same
    # way retrieve/generate are patched at their use-site module.
    monkeypatch.setattr(ai_opinion_service, "SessionLocal", SessionLocal)
    with SessionLocal() as db:
        event = _make_event(db)
        event_id = event.id
        opinion = ai_opinion_service.create_pending_opinion(db, "mystery.evtx", sample_event_ids=[event_id])
        opinion_id = opinion.id

    monkeypatch.setattr(ai_opinion_service, "retrieve", lambda query, k: SAMPLE_CHUNKS)
    monkeypatch.setattr(
        ai_opinion_service,
        "generate",
        lambda messages: (
            "Nothing here looks unusual.\n\n"
            "## Assessment: Nothing unusual noted\n\n"
            "## Limitations\n- Only a small sample of this file's uncovered events was reviewed."
        ),
    )

    ai_opinion_service.fill_in_opinion(opinion_id, "mystery.evtx", [event_id])

    with SessionLocal() as db:
        opinion = db.get(AiOpinion, opinion_id)
        assert opinion.status == "ready"
        assert opinion.assessment_label == "nothing_unusual"
        assert "Nothing here looks unusual" in opinion.summary
        assert opinion.error is None
        # Limitations always populated alongside a successful summary,
        # independent of the assessment (guardrail: assessment + limitations
        # can coexist -- see prompts.py's UNCOVERED_LIMITATIONS_HEADING).
        assert "small sample" in opinion.limitations
        # A "nothing unusual" verdict offers no technique candidates --
        # listing techniques beside "nothing stands out" reads as an
        # accusation the opinion itself does not make.
        assert opinion.attack_candidate_ids == []


def test_fill_in_opinion_worth_reviewing_offers_only_well_matched_candidates(api_client, monkeypatch):
    _client, SessionLocal = api_client
    monkeypatch.setattr(ai_opinion_service, "SessionLocal", SessionLocal)
    with SessionLocal() as db:
        event_id = _make_event(db).id
        opinion_id = ai_opinion_service.create_pending_opinion(db, "m.evtx", sample_event_ids=[event_id]).id

    chunks = [
        {**SAMPLE_CHUNKS[0], "score": 0.56},
        {"chunk_id": "x", "document": "d", "score": 0.43,
         "metadata": {"source_type": "mitre_technique", "technique_id": "T1547.010"}},
    ]
    monkeypatch.setattr(ai_opinion_service, "retrieve", lambda query, k: chunks)
    monkeypatch.setattr(
        ai_opinion_service,
        "generate",
        lambda messages: "Odd.\n\n## Assessment: Worth reviewing\n\n## Limitations\n- small sample",
    )

    ai_opinion_service.fill_in_opinion(opinion_id, "m.evtx", [event_id])

    with SessionLocal() as db:
        opinion = db.get(AiOpinion, opinion_id)
        assert opinion.assessment_label == "worth_reviewing"
        # sourced only from retrieved MITRE chunk metadata, and only above
        # the relevance floor -- the 0.43 neighbour is not offered
        assert opinion.attack_candidate_ids == [SAMPLE_CHUNKS[0]["metadata"]["technique_id"]]


def test_fill_in_opinion_withholds_technique_documents_when_the_file_already_has_detections(api_client, monkeypatch):
    """10 Oct 2026 audit: a capture detected as sAMAccountName spoofing was
    described by the review as "silver tickets", a technique the search had
    returned for a ticket request. With detections present the review gets no
    technique documents and offers no technique candidates."""
    _client, SessionLocal = api_client
    monkeypatch.setattr(ai_opinion_service, "SessionLocal", SessionLocal)
    with SessionLocal() as db:
        event_id = _make_event(db).id
        opinion_id = ai_opinion_service.create_pending_opinion(db, "m.evtx", sample_event_ids=[event_id]).id

    playbook = {"chunk_id": "p", "document": "triage guidance", "score": 0.6, "metadata": {"source_type": "playbook"}}
    monkeypatch.setattr(ai_opinion_service, "retrieve", lambda query, k: [{**SAMPLE_CHUNKS[0], "score": 0.56}, playbook])
    seen = {}

    def fake_generate(messages):
        seen["prompt"] = "\n".join(str(m.content) for m in messages)
        return "Odd.\n\n## Assessment: Worth reviewing\n\n## Limitations\n- small sample"

    monkeypatch.setattr(ai_opinion_service, "generate", fake_generate)

    ai_opinion_service.fill_in_opinion(opinion_id, "m.evtx", [event_id], matched_rule_titles=["Some Real Detection"])

    assert "triage guidance" in seen["prompt"]
    assert SAMPLE_CHUNKS[0]["document"] not in seen["prompt"]
    with SessionLocal() as db:
        assert db.get(AiOpinion, opinion_id).attack_candidate_ids == []


def test_fill_in_opinion_marks_invented_technique_ids(api_client, monkeypatch):
    _client, SessionLocal = api_client
    monkeypatch.setattr(ai_opinion_service, "SessionLocal", SessionLocal)
    with SessionLocal() as db:
        event_id = _make_event(db).id
        opinion_id = ai_opinion_service.create_pending_opinion(db, "m.evtx", sample_event_ids=[event_id]).id

    monkeypatch.setattr(ai_opinion_service, "retrieve", lambda query, k: [])
    monkeypatch.setattr(
        ai_opinion_service,
        "generate",
        lambda messages: "Looks like T9999.123.\n\n## Assessment: Worth reviewing\n\n## Limitations\n- x",
    )
    ai_opinion_service.fill_in_opinion(opinion_id, "m.evtx", [event_id])
    with SessionLocal() as db:
        assert "T9999.123 [unverified" in db.get(AiOpinion, opinion_id).summary


def test_fill_in_opinion_llm_failure_marks_status_failed_with_error(api_client, monkeypatch):
    _client, SessionLocal = api_client
    monkeypatch.setattr(ai_opinion_service, "SessionLocal", SessionLocal)
    with SessionLocal() as db:
        event = _make_event(db)
        event_id = event.id
        opinion = ai_opinion_service.create_pending_opinion(db, "mystery.evtx", sample_event_ids=[event_id])
        opinion_id = opinion.id

    monkeypatch.setattr(ai_opinion_service, "retrieve", lambda query, k: [])

    def raise_error(messages):
        raise LLMProviderError("quota exceeded")

    monkeypatch.setattr(ai_opinion_service, "generate", raise_error)

    ai_opinion_service.fill_in_opinion(opinion_id, "mystery.evtx", [event_id])

    with SessionLocal() as db:
        opinion = db.get(AiOpinion, opinion_id)
        assert opinion.status == "failed"
        assert "quota exceeded" in opinion.error
        assert opinion.assessment_label is None
        assert opinion.limitations is None
        assert opinion.attack_candidate_ids is None


def test_fill_in_opinion_never_creates_an_alert_or_incident(api_client, monkeypatch):
    """The hard constraint: an AI opinion must never manifest as a real
    detection, however it resolves -- including its structured fields
    (limitations, attack_candidate_ids), which must never get merged into
    Incident.mitre_technique_ids or influence severity_service in any way."""
    _client, SessionLocal = api_client
    monkeypatch.setattr(ai_opinion_service, "SessionLocal", SessionLocal)
    with SessionLocal() as db:
        event = _make_event(db)
        event_id = event.id
        opinion = ai_opinion_service.create_pending_opinion(db, "mystery.evtx", sample_event_ids=[event_id])
        opinion_id = opinion.id

    monkeypatch.setattr(ai_opinion_service, "retrieve", lambda query, k: SAMPLE_CHUNKS)
    monkeypatch.setattr(
        ai_opinion_service,
        "generate",
        lambda messages: (
            "This looks concerning.\n\n## Assessment: Worth reviewing\n\n## Limitations\n- Small sample."
        ),
    )

    # No rule matched this file, so a technique candidate IS offered (with
    # detections present they are withheld -- see the test above); the point
    # here is that even an offered candidate never reaches detection state.
    ai_opinion_service.fill_in_opinion(opinion_id, "mystery.evtx", [event_id])

    with SessionLocal() as db:
        from app.models.alert import Alert
        from app.models.incident import Incident

        assert db.query(Alert).count() == 0
        assert db.query(Incident).count() == 0
        opinion = db.get(AiOpinion, opinion_id)
        assert opinion.assessment_label == "worth_reviewing"
        # A real ATT&CK candidate was surfaced (T1003, from SAMPLE_CHUNKS)
        # yet no Incident row exists at all to hold it -- confirming the
        # structured fields have no path into detection/incident state.
        assert opinion.attack_candidate_ids == ["T1003"]
        assert db.query(Incident).count() == 0


def test_event_summary_never_includes_raw_json_fields():
    """`event_data` (the flattened, already-normalized field dict) is now
    intentionally included -- see _event_summary's docstring -- but the
    *raw* XML record and anything outside `raw_json["normalized"]["event_data"]`
    must still never reach the LLM."""
    event = Event(
        id=1,
        host="DC1",
        timestamp=datetime(2026, 8, 30, 9, 0, 0, tzinfo=timezone.utc),
        event_id=4624,
        channel="Security",
        process="cmd.exe",
        command_line="cmd.exe /c whoami",
        user="alice",
        raw_json={
            "raw": {"secret_raw_xml_field": "should never appear"},
            "normalized": {
                "event_data": {"TargetUserName": "alice"},
                "secret_normalized_sibling_field": "should never appear either",
            },
        },
    )

    summary = ai_opinion_service._event_summary(event, group_total=17)

    assert set(summary.keys()) == {
        "why_sampled",
        "channel",
        "event_id",
        "event_type",
        "rpc_interface_name",
        "host",
        "timestamp",
        "process",
        "command_line",
        "user",
        "event_data",
        "group_total_occurrences",
    }
    assert summary["event_data"] == {"TargetUserName": "alice"}
    assert summary["group_total_occurrences"] == 17
    assert "secret_raw_xml_field" not in str(summary)
    assert "secret_normalized_sibling_field" not in str(summary)


def test_event_summary_handles_missing_raw_json_shape():
    """A pre-migration or otherwise malformed raw_json (no "normalized"
    key) must degrade to an empty event_data, never raise."""
    event = Event(
        id=1,
        host="DC1",
        timestamp=datetime(2026, 8, 30, 9, 0, 0, tzinfo=timezone.utc),
        event_id=4624,
        channel="Security",
        raw_json={},
    )

    summary = ai_opinion_service._event_summary(event, group_total=None)

    assert summary["event_data"] == {}
    assert summary["group_total_occurrences"] is None


# -- event_type labeling (regression: caught live -- the model, given only --
# -- a bare numeric event_id, guessed Sysmon event 5 ("Process Terminated") -
# -- meant "process creation" and said so in its own reasoning) -------------


def test_event_summary_labels_known_sysmon_event_types():
    event = Event(
        id=1,
        host="LAPTOP-5GVGMJ14",
        timestamp=datetime(2026, 9, 10, 16, 30, 27, tzinfo=timezone.utc),
        event_id=5,
        channel="Microsoft-Windows-Sysmon/Operational",
        raw_json={},
    )
    summary = ai_opinion_service._event_summary(event, group_total=None)
    assert summary["event_type"] == "Process Terminated"


def test_event_summary_omits_event_type_for_unmapped_sysmon_event_id():
    """An id detection/event_names.py has no verified name for must not get
    a fabricated label -- absent, not a guess, so format_event_samples'
    None-filtering drops it cleanly."""
    event = Event(
        id=1,
        host="H",
        timestamp=datetime(2026, 9, 10, 16, 30, 27, tzinfo=timezone.utc),
        event_id=255,
        channel="Microsoft-Windows-Sysmon/Operational",
        raw_json={},
    )
    summary = ai_opinion_service._event_summary(event, group_total=None)
    assert summary["event_type"] is None


def test_event_summary_never_labels_a_non_sysmon_channels_event_id():
    """Raw Windows event ids are not unique across channels -- Security
    event 5 means something entirely unrelated to Sysmon event 5 (Process
    Terminated). Labeling it with the Sysmon table would just trade one
    mislabeling for another."""
    event = Event(
        id=1,
        host="H",
        timestamp=datetime(2026, 9, 10, 16, 30, 27, tzinfo=timezone.utc),
        event_id=5,
        channel="Security",
        raw_json={},
    )
    summary = ai_opinion_service._event_summary(event, group_total=None)
    assert summary["event_type"] is None


# -- Anti-hallucination: attack_candidate_ids sourced only from retrieved --
# -- MITRE metadata, never from the LLM's own text (guardrail 2's ---------
# -- enforcement point) ----------------------------------------------------


def test_attack_candidate_ids_only_from_mitre_technique_chunks():
    chunks = [SAMPLE_CHUNKS[0], SAMPLE_PLAYBOOK_CHUNK]  # mitre_technique + playbook, same technique_id
    assert ai_opinion_service._attack_candidate_ids(chunks) == ["T1003"]


def test_attack_candidate_ids_ignores_playbook_only_chunks():
    assert ai_opinion_service._attack_candidate_ids([SAMPLE_PLAYBOOK_CHUNK]) == []


def test_attack_candidate_ids_empty_when_no_chunks_retrieved():
    assert ai_opinion_service._attack_candidate_ids([]) == []


def test_attack_candidate_ids_deduplicates_and_skips_missing_ids():
    chunks = [
        SAMPLE_CHUNKS[0],
        {**SAMPLE_CHUNKS[0], "chunk_id": "T1003-mitre-1"},  # same technique_id again
        {"chunk_id": "no-id", "document": "...", "metadata": {"source_type": "mitre_technique"}, "score": 0.5},
    ]
    assert ai_opinion_service._attack_candidate_ids(chunks) == ["T1003"]


def test_fill_in_opinion_attack_candidate_ids_is_never_a_superset_of_retrieved_metadata(api_client, monkeypatch):
    """Structural anti-hallucination assertion: whatever the LLM's prose
    says, the persisted attack_candidate_ids can only ever be a subset of
    the technique_ids this run's retrieve() actually returned."""
    _client, SessionLocal = api_client
    monkeypatch.setattr(ai_opinion_service, "SessionLocal", SessionLocal)
    with SessionLocal() as db:
        event = _make_event(db)
        event_id = event.id
        opinion = ai_opinion_service.create_pending_opinion(db, "mystery.evtx", sample_event_ids=[event_id])
        opinion_id = opinion.id

    monkeypatch.setattr(ai_opinion_service, "retrieve", lambda query, k: SAMPLE_CHUNKS)  # only T1003 retrieved
    monkeypatch.setattr(
        ai_opinion_service,
        "generate",
        # The model's prose invents an unretrieved technique -- this must
        # never leak into the structured field.
        lambda messages: "This looks like T1055 process injection.\n\n## Assessment: Worth reviewing",
    )

    ai_opinion_service.fill_in_opinion(opinion_id, "mystery.evtx", [event_id])

    with SessionLocal() as db:
        opinion = db.get(AiOpinion, opinion_id)
        assert "T1055" in opinion.summary  # the free-text prose is untouched
        retrieved_ids = {c["metadata"]["technique_id"] for c in SAMPLE_CHUNKS}
        assert set(opinion.attack_candidate_ids) <= retrieved_ids
        assert "T1055" not in opinion.attack_candidate_ids


# -- Matched-rule context (guardrail 1's scoping tie-in: the opinion must --
# -- stay additive, never re-litigate what a rule already caught) ---------


def test_fill_in_opinion_passes_matched_rule_titles_into_the_prompt(api_client, monkeypatch):
    _client, SessionLocal = api_client
    monkeypatch.setattr(ai_opinion_service, "SessionLocal", SessionLocal)
    with SessionLocal() as db:
        event = _make_event(db)
        event_id = event.id
        opinion = ai_opinion_service.create_pending_opinion(db, "mystery.evtx", sample_event_ids=[event_id])
        opinion_id = opinion.id

    monkeypatch.setattr(ai_opinion_service, "retrieve", lambda query, k: [])
    captured = {}

    def capture_generate(messages):
        captured["messages"] = messages
        return "Nothing else stands out.\n\n## Assessment: Nothing unusual noted"

    monkeypatch.setattr(ai_opinion_service, "generate", capture_generate)

    ai_opinion_service.fill_in_opinion(
        opinion_id, "mystery.evtx", [event_id], matched_rule_titles=["PowerShell Execution Policy Bypass"]
    )

    rendered = "\n".join(m.content for m in captured["messages"])
    assert "PowerShell Execution Policy Bypass" in rendered


def test_fill_in_opinion_matched_rule_titles_defaults_to_no_rule_matched(api_client, monkeypatch):
    """The zero-rule-match case (unchanged from before this feature) must
    still render cleanly with no titles supplied."""
    _client, SessionLocal = api_client
    monkeypatch.setattr(ai_opinion_service, "SessionLocal", SessionLocal)
    with SessionLocal() as db:
        event = _make_event(db)
        event_id = event.id
        opinion = ai_opinion_service.create_pending_opinion(db, "mystery.evtx", sample_event_ids=[event_id])
        opinion_id = opinion.id

    monkeypatch.setattr(ai_opinion_service, "retrieve", lambda query, k: [])
    captured = {}

    def capture_generate(messages):
        captured["messages"] = messages
        return "Nothing stands out.\n\n## Assessment: Nothing unusual noted"

    monkeypatch.setattr(ai_opinion_service, "generate", capture_generate)

    ai_opinion_service.fill_in_opinion(opinion_id, "mystery.evtx", [event_id])  # no matched_rule_titles arg

    rendered = "\n".join(m.content for m in captured["messages"])
    assert "no rule matched anywhere in this file" in rendered


# -- Malformed LLM output degrades safely (no crash, no fabricated fields) -


def test_fill_in_opinion_malformed_output_leaves_structured_fields_none(api_client, monkeypatch):
    _client, SessionLocal = api_client
    monkeypatch.setattr(ai_opinion_service, "SessionLocal", SessionLocal)
    with SessionLocal() as db:
        event = _make_event(db)
        event_id = event.id
        opinion = ai_opinion_service.create_pending_opinion(db, "mystery.evtx", sample_event_ids=[event_id])
        opinion_id = opinion.id

    monkeypatch.setattr(ai_opinion_service, "retrieve", lambda query, k: [])
    # No recognized "## Assessment: ..." heading and no "## Limitations"
    # heading at all -- simulates the model not following the format.
    monkeypatch.setattr(ai_opinion_service, "generate", lambda messages: "just some unstructured prose")

    ai_opinion_service.fill_in_opinion(opinion_id, "mystery.evtx", [event_id])

    with SessionLocal() as db:
        opinion = db.get(AiOpinion, opinion_id)
        assert opinion.status == "ready"  # generation succeeded, just unparseable
        assert opinion.summary == "just some unstructured prose"
        assert opinion.assessment_label == "uncertain"  # extract_assessment_label's documented safe default
        assert opinion.limitations is None  # "" from the extractor, stored as None, not an empty string
        assert opinion.attack_candidate_ids == []  # no chunks retrieved -- a real empty list, not fabricated


# -- Sampling correctness: group totals and stable ordering ----------------


# -- Retrieval query includes event_data (regression: this was silently ---
# -- missed when event_data was added to _event_summary -- caught by a ----
# -- real end-to-end run against a real BITS-abuse fixture, where the ------
# -- query without it scored 0.42-0.47 and surfaced the wrong techniques --
# -- (T1216.001, T1547.010) instead of the KB's real T1197 "BITS Jobs" -----
# -- chunk, which scores 0.52-0.58 once the query actually contains any ---
# -- BITS-related term.) ----------------------------------------------------


def test_build_retrieval_query_includes_event_data_string_values():
    samples = [
        {
            "channel": "Microsoft-Windows-Bits-Client/Operational",
            "process": None,
            "command_line": None,
            "event_data": {"jobTitle": "Font Download", "url": "https://fs.microsoft.com/x"},
        }
    ]
    query = ai_opinion_service._build_retrieval_query("bits_openvpn.evtx", samples)
    assert "Font Download" in query
    assert "https://fs.microsoft.com/x" in query


def test_build_retrieval_query_skips_non_string_event_data_values():
    """GUID-shaped strings are still fine to include (harmless noise for a
    semantic search), but non-string values (ints, None, nested dicts) must
    not crash str-joining or pollute the query with Python repr noise."""
    samples = [
        {
            "channel": "Microsoft-Windows-Bits-Client/Operational",
            "process": None,
            "command_line": None,
            "event_data": {
                "fileCount": 1,
                "bytesTransferred": None,
                "nested": {"a": 1},
                "jobTitle": "Font Download",
            },
        }
    ]
    query = ai_opinion_service._build_retrieval_query("bits_openvpn.evtx", samples)
    assert "Font Download" in query
    assert "{'a': 1}" not in query
    assert "None" not in query.split("Font Download")[0].split()  # no stray "None" token


def test_build_retrieval_query_handles_missing_or_empty_event_data():
    samples_missing = [{"channel": "Security", "process": "cmd.exe", "command_line": "whoami"}]
    samples_empty = [{"channel": "Security", "process": "cmd.exe", "command_line": "whoami", "event_data": {}}]
    assert "cmd.exe" in ai_opinion_service._build_retrieval_query("a.evtx", samples_missing)
    assert "cmd.exe" in ai_opinion_service._build_retrieval_query("a.evtx", samples_empty)


def test_fill_in_opinion_includes_group_total_occurrences(api_client, monkeypatch):
    from app.services.ingest_service import UncoveredEventGroup

    _client, SessionLocal = api_client
    monkeypatch.setattr(ai_opinion_service, "SessionLocal", SessionLocal)
    with SessionLocal() as db:
        event = _make_event(db, channel="Microsoft-Windows-PowerShell/Operational", event_id=40961)
        event_id = event.id
        opinion = ai_opinion_service.create_pending_opinion(db, "mystery.evtx", sample_event_ids=[event_id])
        opinion_id = opinion.id

    monkeypatch.setattr(ai_opinion_service, "retrieve", lambda query, k: [])
    captured = {}

    def capture_generate(messages):
        captured["messages"] = messages
        return "Nothing stands out.\n\n## Assessment: Nothing unusual noted"

    monkeypatch.setattr(ai_opinion_service, "generate", capture_generate)

    breakdown = [UncoveredEventGroup(channel="Microsoft-Windows-PowerShell/Operational", event_id=40961, count=769)]
    ai_opinion_service.fill_in_opinion(opinion_id, "mystery.evtx", [event_id], uncovered_breakdown=breakdown)

    rendered = "\n".join(m.content for m in captured["messages"])
    assert "group_total_occurrences: 769" in rendered


def test_fill_in_opinion_reorders_events_to_match_sample_event_ids(api_client, monkeypatch):
    """Event.id.in_(...) gives no ordering guarantee -- the events summarized
    must follow sample_event_ids's own order (the round-robin selection
    order), not arbitrary DB return order."""
    _client, SessionLocal = api_client
    monkeypatch.setattr(ai_opinion_service, "SessionLocal", SessionLocal)
    with SessionLocal() as db:
        event_a = _make_event(db, event_id=1)
        event_b = _make_event(db, event_id=2)
        # Request b before a -- opposite of insertion/id order.
        opinion = ai_opinion_service.create_pending_opinion(
            db, "mystery.evtx", sample_event_ids=[event_b.id, event_a.id]
        )
        opinion_id = opinion.id
        ordered_ids = [event_b.id, event_a.id]

    monkeypatch.setattr(ai_opinion_service, "retrieve", lambda query, k: [])
    captured = {}

    def capture_generate(messages):
        captured["messages"] = messages
        return "Nothing stands out.\n\n## Assessment: Nothing unusual noted"

    monkeypatch.setattr(ai_opinion_service, "generate", capture_generate)

    ai_opinion_service.fill_in_opinion(opinion_id, "mystery.evtx", ordered_ids)

    rendered = "\n".join(m.content for m in captured["messages"])
    # event_id: 2 (event_b) must be rendered as sample [1], before event_id: 1.
    assert rendered.index("event_id: 2") < rendered.index("event_id: 1")


def _summary_type(channel, event_id):
    event = Event(
        id=1,
        host="H",
        timestamp=datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc),
        event_id=event_id,
        channel=channel,
        raw_json={},
    )
    return ai_opinion_service._event_summary(event, group_total=None)["event_type"]


def test_event_summary_names_the_event_types_the_model_got_wrong_in_the_audit():
    """10 Oct 2026 fixture audit: with no name to go on, the review called a
    pipe connection "pipe creation" and an account being enabled "creation"."""
    assert _summary_type("Microsoft-Windows-Sysmon/Operational", 18) == "Pipe Connected"
    assert _summary_type("Microsoft-Windows-Sysmon/Operational", 17) == "Pipe Created"
    assert _summary_type("Security", 4722) == "User Account Enabled"
    assert _summary_type("Security", 4741) == "Computer Account Created"
    assert _summary_type("Security", 4769) == "Kerberos Service Ticket Requested"
    assert _summary_type("Security", 5156) == "Network Connection Allowed"


def test_event_names_are_looked_up_per_channel():
    from app.detection.event_names import event_type_name

    assert event_type_name("sysmon", 1) == "Process Creation"
    assert event_type_name("system", 1) is None  # System 1 is a clock change, not a process
    assert event_type_name(None, 4624) is None
    assert event_type_name("security", 4624) == "Logon"


def test_prompt_forbids_guessing_what_a_listed_detection_matched():
    from app.rag.prompts import UNCOVERED_OPINION_SYSTEM_PROMPT

    assert "only the NAMES of those detections" in UNCOVERED_OPINION_SYSTEM_PROMPT
    assert "never state or guess which event, field or value a listed detection matched" in UNCOVERED_OPINION_SYSTEM_PROMPT


def test_rpc_interfaces_are_named_from_the_documented_table_only():
    from app.detection.event_names import rpc_interface_name

    # the UUID the review twice called "the EFSRPC interface" in the audit
    assert rpc_interface_name("{367abb81-9844-35f1-ad32-98f038001003}") == "Service Control Manager (svcctl)"
    assert "EFSRPC" in rpc_interface_name("{C681D488-D850-11D0-8C52-00C04FD90F7E}")
    assert rpc_interface_name("{fb8a0729-2d04-4658-be93-27b4ad553fac}") is None  # not in the table: stays unnamed
    assert rpc_interface_name(None) is None


def test_event_summary_carries_the_rpc_interface_name_when_known():
    def summary(uuid):
        event = Event(
            id=1,
            host="H",
            timestamp=datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc),
            event_id=5,
            channel="Microsoft-Windows-RPC",
            raw_json={"normalized": {"event_data": {"InterfaceUuid": uuid}}},
        )
        return ai_opinion_service._event_summary(event, group_total=None)

    assert summary("{367abb81-9844-35f1-ad32-98f038001003}")["rpc_interface_name"] == "Service Control Manager (svcctl)"
    assert summary("{00000134-0000-0000-c000-000000000046}")["rpc_interface_name"] is None


def test_prompt_forbids_identifying_an_unnamed_identifier_or_citing_an_unshown_technique():
    from app.rag.prompts import UNCOVERED_OPINION_SYSTEM_PROMPT

    assert "`rpc_interface_name`" in UNCOVERED_OPINION_SYSTEM_PROMPT
    assert "the interface is unidentified" in UNCOVERED_OPINION_SYSTEM_PROMPT
    assert "A retrieved technique is only a search result" in UNCOVERED_OPINION_SYSTEM_PROMPT
