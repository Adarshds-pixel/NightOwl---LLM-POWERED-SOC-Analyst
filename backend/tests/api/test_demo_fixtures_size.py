"""Demo Mode must only offer captures that finish in seconds."""

import json

from app.api import routes_demo


def test_demo_fixture_list_skips_captures_too_large_for_a_live_demo(api_client, tmp_path, monkeypatch):
    client, _SessionLocal = api_client
    (tmp_path / "small.evtx").write_bytes(b"x" * 100)
    (tmp_path / "huge.evtx").write_bytes(b"x" * (routes_demo.DEMO_MAX_FIXTURE_BYTES + 1))
    matrix = tmp_path / "matrix.json"
    matrix.write_text(
        json.dumps(
            [
                {"name": "small.evtx", "correct_technique": True, "mitre_technique_ids": ["T1"], "behavior_hint": "small"},
                {"name": "huge.evtx", "correct_technique": True, "mitre_technique_ids": ["T2"], "behavior_hint": "huge"},
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(routes_demo, "FAILURE_MATRIX_PATH", matrix)
    monkeypatch.setattr(routes_demo, "DETECTED_FIXTURES_DIR", tmp_path)

    names = [f["filename"] for f in client.get("/demo/fixtures").json()["fixtures"]]

    assert names == ["small.evtx"]
