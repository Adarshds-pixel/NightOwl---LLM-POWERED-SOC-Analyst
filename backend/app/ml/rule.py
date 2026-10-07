"""The pseudo-rule the ML anomaly layer files its alerts under.

An ML alert has a rule_id (`ml-anomaly-detector`) but no YAML file, like a
sequence-engine match, so every read path that resolves an Alert's rule_id to
a title merges this in (detection/synthetic.py's NON_YAML_RULES).

This module deliberately imports nothing from app.detection, so
app/detection/synthetic.py can merge it in without a circular import.
"""

from dataclasses import dataclass, field

ML_RULE_ID = "ml-anomaly-detector"


@dataclass(frozen=True)
class MLAnomalyRule:
    """The title/technique/severity an ML alert carries.

    Shaped like detection.sequences.SequencePattern so the same
    `rules_by_id.get(...)` lookups work -- except technique_id is `None` by
    design: an anomaly score says "this window does not look like this
    family's benign baseline", which maps to no single ATT&CK technique, and a
    fabricated one would be invented confidence.
    """

    rule_id: str = ML_RULE_ID
    title: str = "ML Behavioural Anomaly"
    technique_id: str | None = None
    tactics: list[str] = field(default_factory=list)
    level: str = "low"
    description: str = (
        "Unsupervised per-log-family model (Ledoit-Wolf Mahalanobis distance over 10-minute host windows of "
        "one channel: Security, Sysmon, System or Application). Flags a window whose event mix and volume sit "
        "beyond the 99.5th percentile of the benign baseline, and records which features drove the score. "
        "Experimental and advisory by default: trained on only two benign hosts, it flags 1-4.5 benign windows "
        "per host-day and cannot yet tell an attack from an unfamiliar machine, so it never opens an incident "
        "or changes one -- it is supporting evidence, never a detection. Windows under 10 events are not "
        "scored; single-event attacks are the rules' job."
    )


ML_ANOMALY_RULE = MLAnomalyRule()
