"""Rules that fire without a YAML file behind them.

Two detectors produce alerts the rule loader knows nothing about: the
multi-event sequence engine (detection/sequences.py) and the ML anomaly layer
(app/ml/). Any read path resolving an Alert's rule_id to a title/technique has
to consult all three sources, or those alerts surface as "Unknown rule".

Merge this instead of SEQUENCE_PATTERNS alone:

    rules_by_id = {r.rule_id: r for r in get_loaded_rules()} | NON_YAML_RULES
"""

from app.detection.sequences import SEQUENCE_PATTERNS
from app.ml.rule import ML_ANOMALY_RULE, ML_RULE_ID

NON_YAML_RULES = SEQUENCE_PATTERNS | {ML_RULE_ID: ML_ANOMALY_RULE}

__all__ = ["NON_YAML_RULES", "SEQUENCE_PATTERNS", "ML_ANOMALY_RULE", "ML_RULE_ID"]
