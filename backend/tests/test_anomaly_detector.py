"""app/ml: per-family features, fitting, scoring, attribution, bundle checks."""

import random
from datetime import datetime, timedelta, timezone

import pytest
import sklearn

from app.ml.detector import (
    MIN_WINDOW_EVENTS,
    AnomalyModelBundle,
    ModelCompatibilityError,
    fit_family,
    new_bundle,
)
from app.ml.features import build_vocabulary, extract_features, family_of, window_start
from app.ml.windows import build_windows, dedupe
from app.schemas.event import NormalizedEvent

T0 = datetime(2026, 5, 1, 9, 0, tzinfo=timezone.utc)
SEC = "Security"


def _ev(event_id, i=0, channel=SEC, host="H", record=None, **data):
    return NormalizedEvent(
        host=host, timestamp=T0 + timedelta(seconds=i), event_id=event_id, channel=channel,
        event_record_id=record, event_data=data, raw={},
    )


def _benign_window(seed: int) -> list[NormalizedEvent]:
    rng = random.Random(seed)
    events = []
    for i in range(rng.randint(20, 40)):
        eid = rng.choice([4624, 4624, 4634, 4672, 5058, 4798])
        events.append(_ev(eid, i, TargetUserName=rng.choice(["alice", "SYSTEM"]), LogonType="5"))
    return events


@pytest.fixture(scope="module")
def security_bundle():
    windows = [_benign_window(s) for s in range(80)]
    model = fit_family("security", windows, ["H"] * len(windows), build_vocabulary(windows))
    return new_bundle({"security": model}, "unit-test")


def test_family_is_channel_aware():
    assert family_of(_ev(1, channel="Microsoft-Windows-Sysmon/Operational")) == "sysmon"
    assert family_of(_ev(1, channel="System")) == "system"
    assert family_of(_ev(1, channel="Microsoft-Windows-Bits-Client/Operational")) is None


def test_windows_never_mix_families_or_hosts():
    events = [_ev(4624, 0), _ev(1, 1, channel="Microsoft-Windows-Sysmon/Operational"), _ev(4624, 2, host="OTHER")]
    keys = set(build_windows(events))
    assert {(k[0], k[1]) for k in keys} == {("H", "security"), ("H", "sysmon"), ("OTHER", "security")}
    assert all(k[2] == window_start(T0) for k in keys)


def test_dedupe_removes_overlapping_exports():
    events = [_ev(4624, 0, record=7), _ev(4624, 0, record=7), _ev(4624, 1, record=8)]
    assert len(dedupe(events)) == 2


def test_features_use_vocabulary_plus_other():
    features = extract_features("security", [_ev(4624), _ev(4624), _ev(9999)], [4624])
    assert features["eid_4624"] == 2 and features["eid_other"] == 1 and features["total_events"] == 3


def test_small_windows_are_not_scored(security_bundle):
    assert security_bundle.score("security", [_ev(4624, i) for i in range(MIN_WINDOW_EVENTS - 1)]) is None


def test_a_lone_logon_cannot_raise_an_anomaly(security_bundle):
    """The old model scored a single ordinary 4624 as a Medium anomaly."""
    assert security_bundle.score("security", [_ev(4624)]) is None


def test_ordinary_window_is_low(security_bundle):
    assert security_bundle.score("security", _benign_window(999)).severity == "low"


def test_failed_logon_burst_is_flagged_and_explained(security_bundle):
    burst = [_ev(4625, i, TargetUserName=f"user{i}", IpAddress="10.9.9.9", LogonType="3") for i in range(60)]
    result = security_bundle.score("security", burst)
    assert result.severity in ("medium", "high")
    assert result.top_features, "a flagged window must say which features drove it"
    assert 4625 in result.novel_event_ids


def test_unmodelled_family_is_not_scored(security_bundle):
    events = [_ev(1, i, channel="Microsoft-Windows-Sysmon/Operational") for i in range(50)]
    assert security_bundle.score("sysmon", events) is None


def test_bundle_round_trip_and_version_guard(security_bundle, tmp_path):
    path = tmp_path / "m.joblib"
    security_bundle.save(path)
    assert set(AnomalyModelBundle.load(path).families) == {"security"}

    security_bundle.sklearn_version = "0.0.1"
    security_bundle.save(path)
    security_bundle.sklearn_version = sklearn.__version__
    with pytest.raises(ModelCompatibilityError):
        AnomalyModelBundle.load(path)


def test_too_few_training_windows_is_refused():
    with pytest.raises(ValueError):
        fit_family("security", [_benign_window(1)] * 5, ["H"] * 5, [4624])
