"""The ML anomaly layer inside services/ingest_service.py, end to end, against
the real shipped model bundle (app/ml/models/anomaly_detector.joblib).

Asserts behaviour, not exact scores: the distances depend on whichever
benign corpus the model was last trained on."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.config import settings
from app.detection.synthetic import NON_YAML_RULES
from app.ml.rule import ML_RULE_ID
from app.ml.runtime import MODEL_PATH, get_detector, reset_detector_cache
from app.models.alert import Alert
from app.models.incident import Incident
from app.services.ingest_service import ingest_records

pytestmark = pytest.mark.use_ml_detector

BASE = datetime(2024, 5, 1, 10, 0, 0, tzinfo=timezone.utc)
needs_model = pytest.mark.skipif(not MODEL_PATH.exists(), reason="no trained model; run scripts/train_ml_model.py")


def _failed_logon(seq: int, computer: str = "MLHOST01", event_id: int = 4625) -> dict:
    stamp = (BASE + timedelta(seconds=seq)).isoformat().replace("+00:00", "Z")
    return {
        "Event": {
            "System": {
                "EventID": event_id,
                "TimeCreated": {"@SystemTime": stamp},
                "Computer": computer,
                "Channel": "Security",
                "EventRecordID": str(50_000 + seq),
            },
            "EventData": {
                "Data": [
                    {"@Name": "TargetUserName", "#text": f"user{seq}"},
                    {"@Name": "IpAddress", "#text": "10.9.9.9"},
                    {"@Name": "LogonType", "#text": "3"},
                    {"@Name": "Status", "#text": "0xc000006d"},
                ]
            },
        }
    }


def _unruled_burst(n: int) -> list[dict]:
    """A volume of an event type no rule or sequence covers (5156, filtering
    platform connection) -- anomalous for the model, invisible to the rules."""
    return [_failed_logon(i, event_id=5156) for i in range(n)]


def _ml_alerts(db):
    return db.query(Alert).filter(Alert.rule_id == ML_RULE_ID).all()


@needs_model
def test_shipped_bundle_loads():
    reset_detector_cache()
    bundle = get_detector()
    assert bundle is not None and bundle.families


@needs_model
def test_tiny_upload_never_scores(api_client):
    _client, SessionLocal = api_client
    with SessionLocal() as db:
        outcome = ingest_records(db, [_failed_logon(i) for i in range(3)], rules=[])
        db.commit()
        assert outcome.ml_anomalies == 0 and _ml_alerts(db) == []


@needs_model
def test_anomalous_window_is_recorded_with_evidence_but_opens_no_incident(api_client, monkeypatch):
    monkeypatch.setattr(settings, "ml_mode", "advisory")
    _client, SessionLocal = api_client
    with SessionLocal() as db:
        outcome = ingest_records(db, _unruled_burst(80), rules=[])
        db.commit()
        alerts = _ml_alerts(db)
        assert outcome.ml_anomalies == len(alerts) >= 1
        # Never counted as rule detections, never an incident on its own.
        assert outcome.rule_matches == 0 and outcome.alerts_created == 0
        assert alerts[0].incident_id is None and db.query(Incident).count() == 0
        details = alerts[0].details
        assert details["kind"] == "ml_anomaly" and details["family"] == "security"
        assert details["top_features"] and details["window_events"] == 80
        assert NON_YAML_RULES[ML_RULE_ID].technique_id is None


@needs_model
def test_alert_mode_may_open_an_incident_without_inventing_a_technique(api_client, monkeypatch):
    monkeypatch.setattr(settings, "ml_mode", "alert")
    _client, SessionLocal = api_client
    with SessionLocal() as db:
        ingest_records(db, _unruled_burst(80), rules=[])
        db.commit()
        alert = _ml_alerts(db)[0]
        incident = db.get(Incident, alert.incident_id)
        assert incident is not None and incident.mitre_technique_ids == []


def test_ml_off_mode_scores_nothing(api_client, monkeypatch):
    monkeypatch.setattr(settings, "ml_mode", "off")
    _client, SessionLocal = api_client
    with SessionLocal() as db:
        outcome = ingest_records(db, [_failed_logon(i) for i in range(80)], rules=[])
        assert outcome.ml_anomalies == 0


def test_scoring_failure_never_fails_the_upload(api_client, monkeypatch):
    class Broken:
        created_at = "x"

        def score(self, family, events):
            raise RuntimeError("boom")

    monkeypatch.setattr("app.services.ingest_service.get_detector", lambda: Broken())
    _client, SessionLocal = api_client
    with SessionLocal() as db:
        outcome = ingest_records(db, [_failed_logon(i) for i in range(30)], rules=[])
        db.commit()
        assert outcome.events_ingested == 30 and outcome.ml_anomalies == 0
