"""Severity scoring v1.1 (recalibrated 2026-09-06): combines a rule's raw
Sigma level with a weight for the MITRE tactic(s) it's tagged with (parsed
from the rule's own `tags:` list by rule_loader.py), so a "medium" rule
tagged command-and-control ranks above a "medium" rule tagged only
persistence -- both start from the same base severity, but the tactic
carries real risk information the raw Sigma level alone doesn't capture.

v1 used a 0/1/2/3 weight tier and capped the total at "critical". Since
every adjacent Sigma level is exactly 1 rank apart, ANY nonzero weight was
enough to escalate a rule by at least one full band, and the only tactics
that carried weight 0 (reconnaissance, resource_development) describe
pre-compromise attacker prep that essentially no host-telemetry detection
rule in this project is tagged with alone. Auditing the real ruleset
(43 rules) against v1 showed 41/43 rules escalated -- every medium/low rule
in the project became high/critical, and every high rule became critical,
making "medium" and "low" mathematically unreachable as a final severity
and "critical" the outcome for nearly everything. That is the bug this
recalibration fixes.

v1.1 keeps the same base-rank table and the same "highest tactic wins,
capped at critical" mechanism, but narrows escalation to a single +1 rank,
reserved for tactics that mark a concrete, defensible increase in realized
attacker leverage: stealing credentials, moving to another host, gathering
data for exfiltration, actively communicating with an attacker, exfiltrating
data, or causing impact. Tactics that describe routine steps common to
findings across the whole severity range (getting a foothold, running code,
persisting, evading defenses, discovering things) no longer escalate on
their own -- a rule's author-declared level is trusted for those, so
medium/low rules tagged only with routine tactics now correctly stay
medium/low, and high rules tagged only with routine tactics stay high
instead of auto-maxing at critical.
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
# rule is tagged with. Only tactics that represent a concrete increase in
# realized attacker leverage (credential theft, spreading to another host,
# staging data, talking to C2, exfiltrating, or causing impact) carry
# weight 1; every other tactic -- including the "attacker got in / ran
# something / stuck around / hid / looked around" steps that appear on
# rules across the whole severity range -- carries weight 0, so those
# rules keep the level their author declared instead of being forced up
# by tag alone. Escalation is intentionally capped at +1 rank (see module
# docstring for why: with adjacent Sigma levels 1 rank apart, any larger
# weight makes "medium"/"low" unreachable). Keys use underscores, matching
# this project's existing rule-tag convention (e.g. "attack.command_and_control"
# in the seed rules), not MITRE's site hyphens.
_TACTIC_WEIGHT: dict[str, int] = {
    "reconnaissance": 0,
    "resource_development": 0,
    "initial_access": 0,
    "execution": 0,
    "persistence": 0,
    "privilege_escalation": 0,
    # ATT&CK v19 split defense-evasion into stealth + defense-impairment;
    # the old name is kept so a stale tag still resolves to the same weight.
    "defense_evasion": 0,
    "stealth": 0,
    "defense_impairment": 0,
    "discovery": 0,
    "credential_access": 1,
    "lateral_movement": 1,
    "collection": 1,
    "command_and_control": 1,
    "exfiltration": 1,
    "impact": 1,
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
