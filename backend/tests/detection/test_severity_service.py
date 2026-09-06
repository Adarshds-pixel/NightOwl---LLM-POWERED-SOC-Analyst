"""Day 10 verification (Pair 1), recalibrated 2026-09-06 (v1.1 weights --
see severity_service.py's module docstring for why): severity_service.py
combines a rule's base Sigma level with a weight for the MITRE tactic(s)
it's tagged with.
"""

from app.services.severity_service import compute_severity, higher_severity


def test_no_tactics_returns_base_level_unchanged():
    assert compute_severity("medium", []) == "medium"
    assert compute_severity("high", []) == "high"


def test_routine_tactic_does_not_escalate():
    # persistence -> weight 0 in v1.1: a medium rule tagged only with a
    # routine tactic keeps its author-declared level.
    assert compute_severity("medium", ["persistence"]) == "medium"


def test_leverage_tactic_bumps_by_one_rank():
    # impact -> weight 1, base "medium" (rank 3) + 1 = rank 4 ("high")
    assert compute_severity("medium", ["impact"]) == "high"


def test_leverage_tactic_capped_at_critical():
    # command_and_control -> weight 1, base "high" (rank 4) + 1 = rank 5,
    # already "critical" -- capping only matters once rank would exceed 5.
    assert compute_severity("high", ["command_and_control"]) == "critical"


def test_multiple_tactics_uses_the_highest_weight():
    # discovery=0, command_and_control=1 -> only the higher one (1) applies:
    # base "low" (rank 2) + 1 = rank 3 = "medium"
    assert compute_severity("low", ["discovery", "command_and_control"]) == "medium"


def test_low_rule_with_only_routine_tactics_stays_low():
    # Regression test for the bug this recalibration fixes: under v1 every
    # medium/low rule in the real ruleset escalated, making these levels
    # mathematically unreachable. discovery is weight 0 in v1.1, so a
    # low-declared rule tagged only discovery (the project's real
    # sensitive_group_account_enumeration.yml) now stays "low".
    assert compute_severity("low", ["discovery"]) == "low"


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
