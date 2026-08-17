"""Day 10 verification (Pair 1): severity_service.py combines a rule's
base Sigma level with a weight for the MITRE tactic(s) it's tagged with.
"""

from app.services.severity_service import compute_severity, higher_severity


def test_no_tactics_returns_base_level_unchanged():
    assert compute_severity("medium", []) == "medium"
    assert compute_severity("high", []) == "high"


def test_low_weight_tactic_bumps_by_one_rank():
    # persistence -> weight 1
    assert compute_severity("medium", ["persistence"]) == "high"


def test_high_weight_tactic_bumps_by_three_ranks_capped_at_critical():
    # impact -> weight 3, base "medium" (rank 3) + 3 = rank 6, capped at 5 (critical)
    assert compute_severity("medium", ["impact"]) == "critical"


def test_multiple_tactics_uses_the_highest_weight():
    # discovery=2, command_and_control=3 -> only the higher one (3) applies:
    # base "low" (rank 2) + 3 = rank 5 = "critical"
    assert compute_severity("low", ["discovery", "command_and_control"]) == "critical"


def test_already_critical_base_level_stays_capped():
    assert compute_severity("critical", ["impact"]) == "critical"


def test_unknown_level_defaults_to_medium_rank():
    assert compute_severity("nonsense", []) == "medium"


def test_unknown_tactic_contributes_zero_weight():
    assert compute_severity("medium", ["some_future_tactic_not_in_the_table"]) == "medium"


def test_higher_severity_picks_the_higher_ranked_label():
    assert higher_severity("low", "high") == "high"
    assert higher_severity("critical", "medium") == "critical"


def test_higher_severity_ties_return_either_equal_value():
    assert higher_severity("medium", "medium") == "medium"
