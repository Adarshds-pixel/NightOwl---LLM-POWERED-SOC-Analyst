"""GET /ml/model: the inspectable summary of the anomaly layer."""

from app.core.config import settings


def test_ml_model_reports_training_and_held_out_results(api_client, monkeypatch):
    client, _SessionLocal = api_client
    monkeypatch.setattr(settings, "ml_mode", "advisory")

    body = client.get("/ml/model").json()

    assert body["mode"] == "advisory"
    if body["ready"]:  # the bundle ships with the repo, but never fail on its absence here
        assert {f["family"] for f in body["families"]} >= {"security", "sysmon"}
        security = next(f for f in body["families"] if f["family"] == "security")
        assert security["train_windows"] > 0
        assert security["threshold_high"] > security["threshold_medium"] > 0
        assert security["held_out"]["alerts_per_host_day"] > 0
        assert "never open or change an incident" in body["explanation"]


def test_ml_model_when_disabled(api_client, monkeypatch):
    client, _SessionLocal = api_client
    monkeypatch.setattr(settings, "ml_mode", "off")

    body = client.get("/ml/model").json()

    assert body["mode"] == "off"
    assert body["ready"] is False
    assert body["families"] == []
