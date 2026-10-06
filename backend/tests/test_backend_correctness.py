"""Regression tests for the backend correctness fixes (normalizer edge cases,
incident grouping, alert de-duplication, cache keys, chat persistence).

Each test names the failure it guards against.
"""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.db.base import Base
from app.detection.engine import RuleMatch
from app.detection.rule_loader import LoadedRule
from app.ingestion.normalizer import EventNormalizationError, canonical_channel, normalize_event
from app.models.alert import Alert
from app.models.chat_message import ChatMessage
from app.models.incident import Incident
from app.rag.llm_client import LLMProviderError
from app.services import severity_service
from app.services.event_service import fit
from app.services.incident_service import find_or_create_incident, incident_cache_key
from app.services.ingest_service import ingest_records

BASE = datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc)


def _engine():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine


def _match(level="high", title="Rule", technique_id="T1059.001", rule_id="r1"):
    return RuleMatch(
        rule_id=rule_id,
        title=title,
        level=level,
        score=severity_service.compute_severity_score(level, []),
        technique_id=technique_id,
    )


def _raw(event_id=1, *, system_time="2026-08-19T12:00:00.000Z", channel="Microsoft-Windows-Sysmon/Operational",
         data=None, computer="HOST-A", record_id=None):
    system = {"EventID": event_id, "TimeCreated": {"@SystemTime": system_time}, "Computer": computer,
              "Channel": channel}
    if record_id is not None:
        system["EventRecordID"] = str(record_id)
    items = [{"@Name": k, "#text": v} for k, v in (data or {}).items()]
    return {"Event": {"System": system, "EventData": {"Data": items}}}


# --- normalizer -------------------------------------------------------------


def test_offsetless_timestamp_is_utc_not_naive():
    """A naive timestamp crashed the ingest sort (naive vs aware compare)."""
    event = normalize_event(_raw(system_time="2026-08-19 12:00:00.000000"))
    assert event.timestamp.tzinfo is not None
    assert event.timestamp.utcoffset() == timedelta(0)


@pytest.mark.parametrize("stamp", ["1601-01-01T00:00:00.000Z", "0001-01-01 00:00:00"])
def test_zeroed_filetime_is_rejected_as_a_record_error(stamp):
    with pytest.raises(EventNormalizationError):
        normalize_event(_raw(system_time=stamp))


def test_nested_data_element_does_not_fail_validation():
    """A <Data> with child elements used to raise a pydantic error the
    ingest path did not catch, 500-ing the whole upload."""
    record = _raw()
    record["Event"]["EventData"]["Data"] = [{"@Name": "Payload", "Binary": {"#text": "00FF"}}]
    event = normalize_event(record)
    assert isinstance(event.event_data["Payload"], str)
    assert "00FF" in event.event_data["Payload"]


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("Microsoft-Windows-Security-Mitigations/KernelMode", None),
        ("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", None),
        ("Microsoft-Windows-SystemDataArchiver/Diagnostic", None),
        ("Security", "security"),
        ("Microsoft-Windows-Sysmon/Operational", "sysmon"),
        ("Windows PowerShell", "powershell"),
    ],
)
def test_channel_matching_is_exact_not_substring(raw, expected):
    assert canonical_channel(raw) == expected


def test_system_event_id_1_is_not_parsed_as_sysmon_process_creation():
    event = normalize_event(_raw(1, channel="System", data={"Image": "x.exe", "CommandLine": "x"}))
    assert event.process is None and event.command_line is None


def test_timestomp_flag_only_on_sysmon_event_2():
    event = normalize_event(_raw(2, channel="Application", data={"CreationUtcTime": "2020-01-01 00:00:00.000"}))
    assert "TimestompSuspected" not in event.event_data


def test_overlong_values_are_clipped_to_their_column():
    assert len(fit("x" * 900, 500)) == 500
    assert fit("short", 500) == "short"
    assert fit(None, 10) is None


# --- incident grouping ------------------------------------------------------


def test_long_attack_stays_one_incident_as_the_window_slides():
    """Grouping used to be anchored on the FIRST alert, splitting an attack
    that ran longer than an hour into two incidents."""
    with Session(_engine()) as db:
        first = find_or_create_incident(db, "H", BASE, _match())
        for minutes in (40, 80, 120):
            same = find_or_create_incident(db, "H", BASE + timedelta(minutes=minutes), _match())
            assert same.id == first.id
        db.commit()
        assert db.scalar(select(Incident).where(Incident.id == first.id)).last_activity_at is not None


def test_investigating_incident_still_absorbs_new_alerts():
    with Session(_engine()) as db:
        first = find_or_create_incident(db, "H", BASE, _match())
        first.status = "investigating"
        db.flush()
        second = find_or_create_incident(db, "H", BASE + timedelta(minutes=5), _match())
        assert second.id == first.id


def test_resolved_incident_does_not_absorb_new_alerts():
    with Session(_engine()) as db:
        first = find_or_create_incident(db, "H", BASE, _match())
        first.status = "resolved"
        db.flush()
        second = find_or_create_incident(db, "H", BASE + timedelta(minutes=5), _match())
        assert second.id != first.id


def test_title_follows_the_most_severe_alert():
    with Session(_engine()) as db:
        incident = find_or_create_incident(db, "H", BASE, _match(level="low", title="Noise"))
        find_or_create_incident(db, "H", BASE + timedelta(minutes=1), _match(level="critical", title="DCSync"))
        assert incident.title.startswith("DCSync")
        assert incident.severity == "critical"


def test_earlier_alert_extends_the_incident_backwards():
    with Session(_engine()) as db:
        incident = find_or_create_incident(db, "H", BASE, _match())
        find_or_create_incident(db, "H", BASE - timedelta(minutes=30), _match())
        created = incident.created_at if incident.created_at.tzinfo else incident.created_at.replace(tzinfo=timezone.utc)
        assert created == BASE - timedelta(minutes=30)


def test_advisory_match_never_changes_title_or_severity():
    with Session(_engine()) as db:
        incident = find_or_create_incident(db, "H", BASE, _match(level="low", title="Noise"))
        find_or_create_incident(
            db, "H", BASE + timedelta(minutes=1), _match(level="critical", title="Anomaly", technique_id=None),
            advisory=True,
        )
        assert incident.title.startswith("Noise") and incident.severity == "low"


def test_cache_key_changes_when_evidence_changes():
    with Session(_engine()) as db:
        incident = find_or_create_incident(db, "H", BASE, _match())
        db.flush()
        before = incident_cache_key(db, incident)
        db.add(Alert(event_id=1, rule_id="r1", matched_at=BASE, severity="high", incident_id=incident.id))
        db.flush()
        assert incident_cache_key(db, incident) != before


# --- alert de-duplication ---------------------------------------------------

ENCODED_RULE = LoadedRule(
    rule_id="enc",
    title="Encoded PowerShell",
    level="high",
    category="process_creation",
    detections={"selection": {"CommandLine|contains": "-enc"}},
    condition="selection",
    yaml_path="<test>",
)


def test_identical_repeat_matches_fold_into_one_alert_with_a_count(api_client):
    _client, SessionLocal = api_client
    records = [
        _raw(system_time=(BASE + timedelta(seconds=i)).isoformat().replace("+00:00", "Z"),
             data={"Image": "C:\\p.exe", "CommandLine": "p.exe -enc AAA"}, record_id=100 + i)
        for i in range(10)
    ]
    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[ENCODED_RULE])
        db.commit()
        alerts = db.scalars(select(Alert)).all()
    assert outcome.rule_matches == 10
    assert len(alerts) == 1
    assert alerts[0].occurrence_count == 10


def test_distinct_command_lines_stay_separate_alerts(api_client):
    _client, SessionLocal = api_client
    records = [
        _raw(system_time=(BASE + timedelta(seconds=i)).isoformat().replace("+00:00", "Z"),
             data={"Image": "C:\\p.exe", "CommandLine": f"p.exe -enc {i}"}, record_id=200 + i)
        for i in range(3)
    ]
    with SessionLocal() as db:
        ingest_records(db, records, rules=[ENCODED_RULE])
        db.commit()
        assert len(db.scalars(select(Alert)).all()) == 3


# --- chat persistence -------------------------------------------------------


def test_failed_llm_call_leaves_no_orphan_user_turn(api_client, monkeypatch):
    client, SessionLocal = api_client
    with SessionLocal() as db:
        incident = Incident(title="t", status="open", severity="high", mitre_technique_ids=[], created_at=BASE, host="H")
        db.add(incident)
        db.commit()
        incident_id = incident.id

    def boom(*_args, **_kwargs):
        raise LLMProviderError("provider down")

    monkeypatch.setattr("app.api.routes_chat.generate_chat_reply", boom)
    response = client.post(f"/incidents/{incident_id}/chat", json={"message": "what happened?"})
    assert response.status_code == 503
    with SessionLocal() as db:
        assert db.scalars(select(ChatMessage)).all() == []


def test_overlong_chat_message_is_rejected(api_client):
    client, _ = api_client
    response = client.post("/incidents/1/chat", json={"message": "x" * 5000})
    assert response.status_code == 422
