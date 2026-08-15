"""Rule-to-technique validation interface (Day 6 Pair 2 scaffold).

Pair 1 uses/extends this on Day 11 to validate each Sigma rule's
`mitre_technique_id` (models/rule.py) against the loaded MITRE dataset.
Deprecated/revoked techniques are reported, not rejected outright --
loader.py deliberately keeps them in the lookup so Pair 1 can decide
their own acceptance policy here instead of this scaffold deciding it
for them.
"""

from collections.abc import Iterable
from dataclasses import dataclass

from app.mitre.loader import load_mitre_techniques


@dataclass(frozen=True)
class TechniqueValidationResult:
    technique_id: str
    is_valid: bool
    is_deprecated: bool = False
    is_revoked: bool = False


def validate_technique_id(technique_id: str) -> TechniqueValidationResult:
    technique = load_mitre_techniques().get(technique_id)
    if technique is None:
        return TechniqueValidationResult(technique_id=technique_id, is_valid=False)
    return TechniqueValidationResult(
        technique_id=technique_id,
        is_valid=True,
        is_deprecated=technique["is_deprecated"],
        is_revoked=technique["is_revoked"],
    )


def validate_technique_ids(technique_ids: Iterable[str]) -> dict[str, TechniqueValidationResult]:
    return {technique_id: validate_technique_id(technique_id) for technique_id in technique_ids}
