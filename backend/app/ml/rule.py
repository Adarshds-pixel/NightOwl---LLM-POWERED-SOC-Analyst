"""The pseudo-rule the ML anomaly layer files its alerts under.

An ML alert has a rule_id (`ml-anomaly-detector`) but no YAML file, exactly
like a sequence-engine match. Every read path that resolves an Alert's rule_id
to a human title looked only at get_loaded_rules() + SEQUENCE_PATTERNS, so ML
alerts rendered as "Unknown rule" in the alerts list, the events view, the
incident view, and the incident narrative -- and `GET /rules/ml-anomaly-detector`
404'd.

This module deliberately imports nothing from app.detection, so
app/detection/synthetic.py can merge it in without a circular import.
"""

from dataclasses import dataclass, field

ML_RULE_ID = "ml-anomaly-detector"


@dataclass(frozen=True)
class MLAnomalyRule:
    """The title/technique/severity an ML alert carries.

    Shaped to match detection.sequences.SequencePattern so the same
    `rules_by_id.get(...)` lookups work unchanged -- except technique_id is
    `None` by design, not by omission: an anomaly score says "this window does
    not look like the baseline", which maps to no single ATT&CK technique. A
    fabricated one would be exactly the kind of invented confidence
    docs/DOCUMENTATION.md §9 forbids.
    """

    rule_id: str = ML_RULE_ID
    title: str = "ML Behavioural Anomaly (Host Window Deviates from Benign Baseline)"
    technique_id: str | None = None
    tactics: list[str] = field(default_factory=list)
    level: str = "medium"
    description: str = (
        "Unsupervised Ledoit-Wolf Mahalanobis model over 10-minute host windows. "
        "Flags windows whose behaviour sits beyond the 99.5th percentile of the "
        "benign baseline. Supplementary evidence of unusual activity -- it does "
        "not identify a specific technique, and single-event stealth executions "
        "are the Sigma rules' job, not this layer's."
    )


ML_ANOMALY_RULE = MLAnomalyRule()
