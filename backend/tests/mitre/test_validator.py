"""Day 6 verification (Pair 2): mitre/validator.py scaffold that Pair 1
will use on Day 11 to validate rules' mitre_technique_id values.
"""

from app.mitre.validator import validate_technique_id, validate_technique_ids

FAKE_LOOKUP = {
    "T1059.001": {
        "id": "T1059.001",
        "name": "PowerShell",
        "description": "...",
        "tactics": ["execution"],
        "is_deprecated": False,
        "is_revoked": False,
    },
    "T1086": {
        "id": "T1086",
        "name": "PowerShell (deprecated)",
        "description": "...",
        "tactics": ["execution"],
        "is_deprecated": True,
        "is_revoked": False,
    },
    "T1000": {
        "id": "T1000",
        "name": "Revoked Technique",
        "description": "...",
        "tactics": [],
        "is_deprecated": False,
        "is_revoked": True,
    },
}


def test_validate_technique_id_valid(monkeypatch):
    monkeypatch.setattr("app.mitre.validator.load_mitre_techniques", lambda: FAKE_LOOKUP)

    result = validate_technique_id("T1059.001")

    assert result.is_valid is True
    assert result.is_deprecated is False
    assert result.is_revoked is False


def test_validate_technique_id_unknown(monkeypatch):
    monkeypatch.setattr("app.mitre.validator.load_mitre_techniques", lambda: FAKE_LOOKUP)

    result = validate_technique_id("T9999.999")

    assert result.is_valid is False
    assert result.is_deprecated is False
    assert result.is_revoked is False


def test_validate_technique_id_flags_deprecated(monkeypatch):
    monkeypatch.setattr("app.mitre.validator.load_mitre_techniques", lambda: FAKE_LOOKUP)

    result = validate_technique_id("T1086")

    assert result.is_valid is True
    assert result.is_deprecated is True


def test_validate_technique_id_flags_revoked(monkeypatch):
    monkeypatch.setattr("app.mitre.validator.load_mitre_techniques", lambda: FAKE_LOOKUP)

    result = validate_technique_id("T1000")

    assert result.is_valid is True
    assert result.is_revoked is True


def test_validate_technique_ids_batch(monkeypatch):
    monkeypatch.setattr("app.mitre.validator.load_mitre_techniques", lambda: FAKE_LOOKUP)

    results = validate_technique_ids(["T1059.001", "T9999.999", "T1086"])

    assert set(results.keys()) == {"T1059.001", "T9999.999", "T1086"}
    assert results["T1059.001"].is_valid is True
    assert results["T9999.999"].is_valid is False
    assert results["T1086"].is_deprecated is True
