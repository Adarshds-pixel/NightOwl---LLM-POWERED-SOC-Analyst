"""GET/POST /demo/* -- the live-replay control surface.

`spawn` is monkeypatched to a no-op for every start here, so these tests
check the HTTP contract (status codes, response shape, the 409 guards)
without ever running a real background thread against the real database.
The actual tick/grouping/stop/finish behaviour is covered directly against
`services/replay_service.py` in `tests/services/test_replay_service.py`.
"""

import functools

import pytest

from app.core.config import settings
from app.services import replay_service


@pytest.fixture(autouse=True)
def _no_op_spawn(api_client, monkeypatch):
    """Routes call `replay_service.start_replay(scenario_id)` with no
    explicit session_factory/spawn, so its defaults (the real Postgres
    SessionLocal, a real thread) would apply unless overridden -- these
    tests only exercise the HTTP layer, so bind both to the in-memory test
    DB and a no-op spawn for every route call made through this fixture.
    """
    _client, SessionLocal = api_client
    bound = functools.partial(replay_service.start_replay, session_factory=SessionLocal, spawn=lambda target: None)
    monkeypatch.setattr("app.api.routes_demo.replay_service.start_replay", bound)


def test_status_is_idle_before_any_run(api_client):
    client, _ = api_client
    response = client.get("/demo/replay/status")
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "idle"
    assert body["run_id"] is None


def test_start_returns_running(api_client):
    client, _ = api_client
    response = client.post("/demo/replay/start", json={"scenario_id": "demo_shift", "reset_first": True})
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "running"
    assert body["scenario_id"] == "demo_shift"
    assert body["run_id"] is not None
    assert body["records_total"] > 0


def test_status_reflects_the_started_run(api_client):
    client, _ = api_client
    started = client.post("/demo/replay/start", json={"scenario_id": "demo_shift"}).json()

    status = client.get("/demo/replay/status").json()
    assert status["run_id"] == started["run_id"]
    assert status["state"] == "running"


def test_double_start_returns_409(api_client):
    client, _ = api_client
    client.post("/demo/replay/start", json={"scenario_id": "demo_shift"})

    response = client.post("/demo/replay/start", json={"scenario_id": "demo_shift"})
    assert response.status_code == 409


def test_unknown_scenario_id_returns_400(api_client):
    client, _ = api_client
    response = client.post("/demo/replay/start", json={"scenario_id": "does-not-exist"})
    assert response.status_code == 400


def test_stop_targets_the_running_run(api_client):
    client, _ = api_client
    started = client.post("/demo/replay/start", json={"scenario_id": "demo_shift"}).json()

    response = client.post("/demo/replay/stop")
    assert response.status_code == 200
    assert response.json()["run_id"] == started["run_id"]


def test_stop_with_nothing_running_returns_idle(api_client):
    client, _ = api_client
    response = client.post("/demo/replay/stop")
    assert response.status_code == 200
    assert response.json()["state"] == "idle"


def test_reset_while_running_returns_409(api_client):
    client, _ = api_client
    client.post("/demo/replay/start", json={"scenario_id": "demo_shift"})

    response = client.post("/demo/reset")
    assert response.status_code == 409


def test_reset_when_idle_returns_deleted_counts(api_client):
    client, _ = api_client
    response = client.post("/demo/reset")
    assert response.status_code == 200
    body = response.json()
    assert set(body["deleted"]) == {"chat_messages", "audit_log", "alerts", "incidents", "events"}
    assert all(count == 0 for count in body["deleted"].values())


def test_demo_mode_disabled_returns_403(api_client, monkeypatch):
    client, _ = api_client
    monkeypatch.setattr(settings, "demo_mode_enabled", False)

    response = client.get("/demo/replay/status")
    assert response.status_code == 403


def test_scenarios_endpoint_returns_provenance(api_client):
    client, _ = api_client
    response = client.get("/demo/scenarios")
    assert response.status_code == 200
    scenarios = response.json()["scenarios"]
    demo_shift = next(s for s in scenarios if s["id"] == "demo_shift")

    assert demo_shift["host"]
    assert len(demo_shift["segments"]) >= 2
    noise = next(s for s in demo_shift["segments"] if s["kind"] == "noise")
    assert noise["source_capture"]
    assert noise["record_count"] > 0
    attack = next(s for s in demo_shift["segments"] if s["kind"] == "attack")
    assert attack["expected_rule_titles"]
    assert attack["expected_technique_ids"]
