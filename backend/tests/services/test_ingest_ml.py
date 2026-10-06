"""The ML anomaly layer inside services/ingest_service.py, end to end.

This path had no coverage at all: tests/conftest.py disabled the detector for
every test except the pure unit tests, so ML windowing, alert creation,
incident grouping and the failure handling were never exercised. These tests
opt back in with @pytest.mark.use_ml_detector and run against the real
trained model in app/ml/models/.

They assert behaviour, not a score: the exact Mahalanobis distance of a given
window is a property of whichever benign corpus the model was last trained on,
and pinning it would make this file a tripwire for every retrain.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.detection.synthetic import NON_YAML_RULES
from app.ml.rule import ML_RULE_ID
from app.ml.runtime import MODEL_PATH, get_detector, reset_detector_cache
from app.models.alert import Alert
from app.models.incident import Incident
from app.services.ingest_service import ingest_records

pytestmark = pytest.mark.use_ml_detector

BASE = datetime(2024, 5, 1, 10, 0, 0, tzinfo=timezone.utc)

needs_model = pytest.mark.skipif(
    not MODEL_PATH.exists(),
    reason="no trained model on disk; run scripts/train_ml_model.py",
)


def _proc_record(seq: int, image: str, computer: str = "MLHOST01") -> dict:
    """A Sysmon EID 1 process-creation record, `seq` seconds after BASE.

    Kept inside one 10-minute bucket by the callers below so the whole batch
    lands in a single window, which is what the detector scores.
    """
    stamp = (BASE + timedelta(seconds=seq)).isoformat().replace("+00:00", "Z")
    return {
        "Event": {
            "System": {
                "EventID": 1,
                "TimeCreated": {"@SystemTime": stamp},
                "Computer": computer,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Provider": {"@Name": "Microsoft-Windows-Sysmon"},
                "EventRecordID": str(10_000 + seq),
            },
            "EventData": {
                "Data": [
                    {"@Name": "Image", "#text": f"C:\\Windows\\System32\\{image}"},
                    {"@Name": "CommandLine", "#text": image},
                    {"@Name": "ParentImage", "#text": "C:\\Windows\\System32\\cmd.exe"},
                    {"@Name": "User", "#text": "MLHOST01\\analyst"},
                ]
            },
        }
    }


def _ml_alerts(db):
    return db.query(Alert).filter(Alert.rule_id == ML_RULE_ID).all()


@needs_model
def test_detector_loads_with_a_feature_schema():
    """A model without bound feature names must not be used -- scoring it
    would depend on extract_features' dict order, which it does not record."""
    reset_detector_cache()
    detector = get_detector()

    assert detector is not None
    assert detector.is_trained
    assert detector.feature_names, "model must carry the schema it was fitted on"


@needs_model
def test_quiet_window_produces_no_ml_alert(api_client):
    """A handful of ordinary process creations is not an anomaly. If this
    starts failing, the model is flagging normal activity."""
    _client, SessionLocal = api_client
    records = [_proc_record(i * 30, image) for i, image in enumerate(["cmd.exe", "notepad.exe", "ping.exe"])]

    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[])
        db.commit()

        assert outcome.events_ingested == 3
        assert _ml_alerts(db) == []


@needs_model
def test_high_volume_window_produces_an_ml_alert(api_client):
    """A 10-minute window with a large burst of distinct processes is exactly
    the volumetric deviation this layer exists to catch."""
    _client, SessionLocal = api_client
    records = [_proc_record(i, f"tool{i}.exe") for i in range(400)]

    with SessionLocal() as db:
        outcome = ingest_records(db, records, rules=[])
        db.commit()

        alerts = _ml_alerts(db)
        assert alerts, "a 400-process burst should deviate from the benign baseline"
        assert outcome.rule_matches >= len(alerts)

        # The alert hangs off a real incident, like any other detection.
        incident = db.get(Incident, alerts[0].incident_id)
        assert incident is not None
        assert incident.host == "MLHOST01"
        # No fabricated ATT&CK technique -- an anomaly score maps to none.
        assert incident.mitre_technique_ids == []


@needs_model
def test_ml_alert_resolves_to_a_real_rule_title(api_client):
    """ML alerts used to render as "Unknown rule" everywhere, because every
    read path resolved rule_id against loaded YAML rules + SEQUENCE_PATTERNS
    only."""
    _client, SessionLocal = api_client
    records = [_proc_record(i, f"tool{i}.exe") for i in range(400)]

    with SessionLocal() as db:
        ingest_records(db, records, rules=[])
        db.commit()

        alert = _ml_alerts(db)[0]

    rule = NON_YAML_RULES.get(alert.rule_id)
    assert rule is not None, "ML rule_id must resolve in the non-YAML rule map"
    assert rule.title and rule.title != "Unknown rule"
    assert rule.technique_id is None


def test_ingest_still_works_when_the_model_is_missing(api_client, monkeypatch):
    """A missing model disables the ML layer; it must not break ingest."""
    _client, SessionLocal = api_client
    monkeypatch.setattr("app.services.ingest_service.get_detector", lambda: None)

    with SessionLocal() as db:
        outcome = ingest_records(db, [_proc_record(0, "cmd.exe")], rules=[])
        db.commit()

        assert outcome.events_ingested == 1
        assert _ml_alerts(db) == []


def test_feature_schema_mismatch_is_logged_and_skipped(api_client, monkeypatch, caplog):
    """If the extractor and the model drift apart, the window is skipped
    loudly rather than scored with a silently wrong vector."""
    _client, SessionLocal = api_client

    class BrokenDetector:
        feature_names = ["a_feature_that_does_not_exist"]

        def select(self, features):
            raise KeyError("feature(s) missing from extraction: ['a_feature_that_does_not_exist']")

        def score_window(self, vec):  # pragma: no cover - never reached
            raise AssertionError("should not score after a select() failure")

    monkeypatch.setattr("app.services.ingest_service.get_detector", lambda: BrokenDetector())

    with SessionLocal() as db, caplog.at_level("ERROR"):
        outcome = ingest_records(db, [_proc_record(0, "cmd.exe")], rules=[])
        db.commit()

        assert outcome.events_ingested == 1
        assert "feature schema mismatch" in caplog.text
        assert _ml_alerts(db) == []
