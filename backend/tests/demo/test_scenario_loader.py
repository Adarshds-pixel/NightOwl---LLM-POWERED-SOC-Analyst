"""Validates the committed demo_shift manifest against the real detection
engine -- these are the tests that make the demo honesty claims ("1,500
real benign events, 0 matches", "these rules fire on these records")
checked facts rather than prose.
"""

from app.demo.scenario_loader import (
    SCENARIOS_DIR,
    ScenarioLoadError,
    get_loaded_scenario,
    load_scenarios,
    load_segment_records,
)
from app.detection.engine import evaluate_event
from app.detection.rule_loader import get_loaded_rules
from app.ingestion.normalizer import normalize_event


def test_demo_shift_scenario_loads():
    scenarios = load_scenarios()
    assert any(scenario.id == "demo_shift" for scenario in scenarios)


def test_every_records_file_exists_and_matches_declared_count():
    scenario = get_loaded_scenario("demo_shift")
    for segment in scenario.segments:
        records = load_segment_records(segment)
        assert len(records) == segment.record_count, segment.id


def test_every_record_normalizes():
    scenario = get_loaded_scenario("demo_shift")
    for segment in scenario.segments:
        for record in load_segment_records(segment):
            normalize_event(record)  # raises EventNormalizationError on failure


def test_noise_segment_produces_zero_matches_through_the_real_engine():
    scenario = get_loaded_scenario("demo_shift")
    noise = next(segment for segment in scenario.segments if segment.kind == "noise")
    rules = get_loaded_rules()

    for record in load_segment_records(noise):
        normalized = normalize_event(record)
        assert evaluate_event(normalized, rules) == [], "noise segment must never trip a rule"


def test_attack_segments_match_their_declared_expectations():
    scenario = get_loaded_scenario("demo_shift")
    rules = get_loaded_rules()

    for segment in scenario.segments:
        if segment.kind != "attack":
            continue

        titles: set[str] = set()
        technique_ids: set[str] = set()
        for record in load_segment_records(segment):
            normalized = normalize_event(record)
            for match in evaluate_event(normalized, rules):
                titles.add(match.title)
                if match.technique_id:
                    technique_ids.add(match.technique_id)

        assert titles == set(segment.expected_rule_titles), segment.id
        assert technique_ids == set(segment.expected_technique_ids), segment.id


def test_attack_segment_anchors_are_more_than_an_hour_apart():
    """Guards the incident-grouping contract (services/incident_service.py's
    1-hour window) against a careless manifest edit collapsing two attack
    segments back into a single incident."""
    scenario = get_loaded_scenario("demo_shift")
    anchors = sorted(segment.offset_minutes for segment in scenario.segments if segment.kind == "attack")
    for earlier, later in zip(anchors, anchors[1:]):
        assert later - earlier > 60, (earlier, later)


def test_unknown_scenario_id_raises():
    try:
        get_loaded_scenario("does-not-exist")
    except ScenarioLoadError:
        pass
    else:
        raise AssertionError("expected ScenarioLoadError")


def test_missing_scenarios_directory_returns_empty_list(tmp_path):
    assert load_scenarios(tmp_path / "does-not-exist") == []


def test_malformed_scenario_file_is_skipped_not_raised(tmp_path):
    (tmp_path / "broken.yml").write_text("id: broken\ntitle: no segments here\n", encoding="utf-8")
    assert load_scenarios(tmp_path) == []


def test_scenarios_dir_points_at_the_committed_directory():
    assert SCENARIOS_DIR.exists()
    assert (SCENARIOS_DIR / "demo_shift.yml").exists()
