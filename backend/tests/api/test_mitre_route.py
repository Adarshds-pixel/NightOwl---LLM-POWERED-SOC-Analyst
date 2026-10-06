"""Day 6 verification (Pair 2): GET /mitre/techniques returns the
technique catalog from mitre/loader.py's cached lookup.
"""

import pytest
from fastapi.testclient import TestClient

from app.core.auth import require_session_auth
from app.core.auth import CSRF_HEADER
from app.main import app


@pytest.fixture(autouse=True)
def _bypass_session_auth():
    """This file doesn't use the `api_client` fixture (no DB needed), so it
    needs its own require_session_auth override -- these tests are about
    the MITRE catalog route, not about auth. See conftest.py's api_client
    fixture for the same rationale."""
    app.dependency_overrides[require_session_auth] = lambda: None
    yield
    app.dependency_overrides.pop(require_session_auth, None)

FAKE_LOOKUP = {
    "T1059.001": {
        "id": "T1059.001",
        "name": "PowerShell",
        "description": "Adversaries may abuse PowerShell...",
        "tactics": ["execution"],
        "is_deprecated": False,
        "is_revoked": False,
    },
    "T1003": {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "description": "Adversaries may attempt to dump credentials...",
        "tactics": ["credential-access"],
        "is_deprecated": False,
        "is_revoked": False,
    },
    "T1086": {
        "id": "T1086",
        "name": "PowerShell (deprecated)",
        "description": "Superseded by T1059.001.",
        "tactics": ["execution"],
        "is_deprecated": True,
        "is_revoked": False,
    },
}


def test_get_mitre_techniques_returns_catalog(monkeypatch):
    monkeypatch.setattr("app.api.routes_mitre.load_mitre_techniques", lambda: FAKE_LOOKUP)
    client = TestClient(app, headers={CSRF_HEADER: "1"})

    response = client.get("/mitre/techniques")

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 3
    assert [t["id"] for t in body["techniques"]] == ["T1003", "T1059.001", "T1086"]


def test_get_mitre_techniques_includes_deprecation_and_revocation_flags(monkeypatch):
    monkeypatch.setattr("app.api.routes_mitre.load_mitre_techniques", lambda: FAKE_LOOKUP)
    client = TestClient(app, headers={CSRF_HEADER: "1"})

    response = client.get("/mitre/techniques")

    techniques_by_id = {t["id"]: t for t in response.json()["techniques"]}
    assert techniques_by_id["T1086"]["is_deprecated"] is True
    assert techniques_by_id["T1059.001"]["is_deprecated"] is False
    assert techniques_by_id["T1059.001"]["tactics"] == ["execution"]


def test_get_mitre_techniques_empty_catalog(monkeypatch):
    monkeypatch.setattr("app.api.routes_mitre.load_mitre_techniques", lambda: {})
    client = TestClient(app, headers={CSRF_HEADER: "1"})

    response = client.get("/mitre/techniques")

    assert response.status_code == 200
    assert response.json() == {"techniques": [], "count": 0}
