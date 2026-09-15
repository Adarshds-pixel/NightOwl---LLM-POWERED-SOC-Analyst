import pytest
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from app.models.event import Event
from app.models.alert import Alert
from app.models.incident import Incident
from app.services.ingest_service import ingest_records
from app.detection.rule_loader import LoadedRule

FAKE_RULE = LoadedRule(
    rule_id="fake-rule-tx",
    title="Fake Tx Rule",
    level="high",
    category="process_creation",
    detections={"selection": {"CommandLine|contains": "malicious"}},
    condition="selection",
    yaml_path="<test>",
    technique_id="T1059",
)

def _record(event_record_id: int, command_line: str = "malicious", computer: str = "WORKSTATION") -> dict:
    return {
        "Event": {
            "System": {
                "EventID": 1,
                "TimeCreated": {"@SystemTime": "2026-08-28T09:00:00+00:00"},
                "Computer": computer,
                "EventRecordID": str(event_record_id)
            },
            "EventData": {"Data": [{"@Name": "CommandLine", "#text": command_line}]},
        }
    }

def test_successful_ingestion_atomic(api_client):
    _client, SessionLocal = api_client
    records = [_record(100)]
    
    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[FAKE_RULE], matched_at=None)
        assert outcome.events_ingested == 1
        assert outcome.alerts_created == 1
        
        # Caller must commit the transaction
        assert db.query(Event).count() == 1
        assert db.query(Alert).count() == 1

def test_detection_failure_rollback(api_client, monkeypatch):
    _client, SessionLocal = api_client
    records = [_record(101)]
    
    def mock_evaluate_event(*args, **kwargs):
        raise ValueError("Simulated detection failure")
    
    monkeypatch.setattr("app.services.ingest_service.evaluate_event", mock_evaluate_event)
    
    with SessionLocal() as db:
        with pytest.raises(ValueError, match="Simulated detection failure"):
            ingest_records(db, records, rules=[FAKE_RULE], matched_at=None)
            
        # Verify rollback - transaction should be reverted automatically or by session dependency
        # since we just raised an exception, ingest_records didn't commit.
        # But let's check a new session to ensure nothing was written to DB.
    
    with SessionLocal() as db_verify:
        assert db_verify.query(Event).count() == 0
        assert db_verify.query(Alert).count() == 0

def test_retry_after_detection_failure(api_client, monkeypatch):
    _client, SessionLocal = api_client
    records = [_record(102)]
    
    call_count = {"count": 0}
    
    # We want it to fail on the first call, succeed on the second
    original_evaluate_event = __import__("app.detection.engine", fromlist=["evaluate_event"]).evaluate_event
    
    def mock_evaluate_event(event, rules):
        if call_count["count"] == 0:
            call_count["count"] += 1
            raise ValueError("Transient failure")
        return original_evaluate_event(event, rules)
        
    monkeypatch.setattr("app.services.ingest_service.evaluate_event", mock_evaluate_event)
    
    # 1. First ingest fails
    with SessionLocal() as db1:
        with pytest.raises(ValueError):
            ingest_records(db1, records, rules=[FAKE_RULE], matched_at=None)
            
    # 2. Verify nothing committed
    with SessionLocal() as db2:
        assert db2.query(Event).count() == 0
        assert db2.query(Alert).count() == 0
        
    # 3. Retry same EVTX
    with SessionLocal() as db3:
        outcome = ingest_records(db3, records, rules=[FAKE_RULE], matched_at=None)
        db3.commit()
        assert outcome.events_ingested == 1
        assert outcome.alerts_created == 1
        
    # 4. Verify successfully inserted and alerts generated
    with SessionLocal() as db4:
        assert db4.query(Event).count() == 1
        assert db4.query(Alert).count() == 1

def test_deduplication_works(api_client):
    _client, SessionLocal = api_client
    records = [_record(103)]
    
    # 1. Normal ingest
    with SessionLocal() as db:
        ingest_records(db, records, rules=[FAKE_RULE], matched_at=None)
        db.commit()
        
    # 2. Duplicate ingest
    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[FAKE_RULE], matched_at=None)
        assert outcome.events_ingested == 0
        assert outcome.duplicate_events_skipped == 1
        assert outcome.alerts_created == 0
