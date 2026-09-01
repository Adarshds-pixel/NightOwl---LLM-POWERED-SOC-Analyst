"""Severity scoring v1 (Day 10): combines a rule's raw Sigma level with a
weight for the MITRE tactic(s) it's tagged with (parsed from the rule's own
`tags:` list by rule_loader.py), so a "medium" rule tagged
command-and-control/impact ranks above a "medium" rule tagged only
reconnaissance -- both start from the same base severity, but the tactic
carries real risk information the raw Sigma level alone doesn't capture.
"""

_BASE_RANK: dict[str, int] = {
    "informational": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}
_DEFAULT_RANK = _BASE_RANK["medium"]

# Weight added on top of the base rank for the highest-weighted tactic a
# rule is tagged with. Grouped loosely by how much real damage/progress an
# attacker gains once a technique in that tactic succeeds -- reconnaissance
# costs nothing yet, command_and_control/exfiltration/impact are the
# tactics that matter most once reached. Keys use underscores, matching
# this project's existing rule-tag convention (e.g. "attack.command_and_control"
# in the seed rules), not MITRE's site hyphens.
_TACTIC_WEIGHT: dict[str, int] = {
    "reconnaissance": 0,
    "resource_development": 0,
    "initial_access": 1,
    "execution": 1,
    "persistence": 1,
    "privilege_escalation": 1,
    "defense_evasion": 1,
    "credential_access": 2,
    "discovery": 2,
    "lateral_movement": 2,
    "collection": 2,
    "command_and_control": 3,
    "exfiltration": 3,
    "impact": 3,
}

_RANK_LABELS = ["informational", "low", "medium", "high", "critical"]
_MAX_RANK = len(_RANK_LABELS)


def _final_rank(base_level: str, tactics: list[str]) -> int:
    """The shared 1-5 rank computation behind both compute_severity (label)
    and compute_severity_score (the same number, kept instead of discarded)
    -- see this module's docstring for what the rank means."""
    base_rank = _BASE_RANK.get(base_level.lower(), _DEFAULT_RANK)
    weight = max((_TACTIC_WEIGHT.get(t.lower(), 0) for t in tactics), default=0)
    return min(base_rank + weight, _MAX_RANK)


def compute_severity(base_level: str, tactics: list[str]) -> str:
    """Combines `base_level` (a rule's raw Sigma `level`, e.g. "high") with
    the highest tactic weight among `tactics`, capped at "critical".
    Unknown levels default to "medium"'s rank; unknown/unrecognized tactics
    contribute 0 weight rather than raising, so a rule tagged with a tactic
    name outside the table above still gets a sane result.
    """
    return _RANK_LABELS[_final_rank(base_level, tactics) - 1]


def compute_severity_score(base_level: str, tactics: list[str]) -> int:
    """The same 1-5 rank compute_severity's label is derived from, kept as a
    number instead of thrown away -- lets the UI show e.g. "Critical - 5/5"
    rather than only ever the label, which collapses "just barely critical"
    and "maximally critical" into an identical badge."""
    return _final_rank(base_level, tactics)


def higher_severity(a: str, b: str) -> str:
    """Returns whichever of two severity labels ranks higher -- used when
    merging a new alert into an existing incident. Unrecognized labels rank
    at "medium" (see compute_severity), same fallback as above.
    """
    rank_a = _BASE_RANK.get(a.lower(), _DEFAULT_RANK)
    rank_b = _BASE_RANK.get(b.lower(), _DEFAULT_RANK)
    return a if rank_a >= rank_b else b
