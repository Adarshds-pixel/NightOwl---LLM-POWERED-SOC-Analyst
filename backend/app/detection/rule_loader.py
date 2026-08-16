"""Loads Sigma-style detection rules from `detection/rules/*.yml` (Day 7).

pySigma (`sigma.rule.SigmaRule.from_yaml`) is used here purely to validate
that each rule file is structurally correct Sigma -- real schema
validation (missing logsource/detection, bad UUID, etc.) with useful error
messages, not decorative. It is *not* used to evaluate rules: pySigma's
backends convert rules into SIEM query languages (Elasticsearch DSL, Splunk
SPL, ...) to run against an external log store, and there's no official
backend for evaluating a rule against a single in-memory Python dict, which
is what engine.py needs. So each rule's `detection` block is separately
parsed with plain `yaml.safe_load` into a small, evaluator-friendly shape
(see LoadedRule) that engine.py consumes directly -- see docs/decisions.md
for the full writeup of this split.

A malformed rule file is logged and skipped, not a startup crash, matching
the existing ingest pipeline's per-record tolerance policy (one bad rule
shouldn't take down detection for every other rule).
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

logger = logging.getLogger(__name__)

RULES_DIR = Path(__file__).resolve().parent / "rules"


class RuleLoadError(Exception):
    pass


@dataclass(frozen=True)
class LoadedRule:
    rule_id: str
    title: str
    level: str
    category: str | None
    # {selection_name: selection_body}, selection_body as pySigma's YAML
    # shape (dict of field[|modifier]: value_or_list) -- see engine.py for
    # how this is evaluated against an event.
    detections: dict[str, object]
    condition: str
    yaml_path: str


def _validate_with_pysigma(text: str, path: Path) -> SigmaRule:
    try:
        return SigmaRule.from_yaml(text)
    except SigmaError as e:
        raise RuleLoadError(f"{path}: invalid Sigma rule: {e}") from e


def _load_one(path: Path) -> LoadedRule:
    text = path.read_text(encoding="utf-8")
    sigma_rule = _validate_with_pysigma(text, path)

    raw = yaml.safe_load(text)
    if not isinstance(raw, dict):
        raise RuleLoadError(f"{path}: rule file did not parse to a YAML mapping")

    detection = raw.get("detection")
    if not isinstance(detection, dict):
        raise RuleLoadError(f"{path}: missing 'detection' block")

    condition = detection.get("condition")
    if not isinstance(condition, str):
        raise RuleLoadError(
            f"{path}: 'detection.condition' must be a single string (v1 limitation, "
            "no named multi-condition rules yet)"
        )

    detections = {name: body for name, body in detection.items() if name != "condition"}
    if not detections:
        raise RuleLoadError(f"{path}: rule has no selections under 'detection'")

    logsource = raw.get("logsource") or {}

    return LoadedRule(
        rule_id=str(sigma_rule.id) if sigma_rule.id else path.stem,
        title=sigma_rule.title,
        level=sigma_rule.level.name.lower() if sigma_rule.level else "unknown",
        category=logsource.get("category"),
        detections=detections,
        condition=condition,
        yaml_path=str(path),
    )


def load_rules(rules_dir: Path = RULES_DIR) -> list[LoadedRule]:
    """Loads every `.yml`/`.yaml` rule in `rules_dir`. Missing directory or
    zero rule files logs a warning and returns [] rather than raising --
    an empty detection engine shouldn't block ingest from working.
    """
    if not rules_dir.exists():
        logger.warning("detection rules directory does not exist: %s", rules_dir)
        return []

    paths = sorted(rules_dir.glob("*.yml")) + sorted(rules_dir.glob("*.yaml"))
    rules: list[LoadedRule] = []
    for path in paths:
        try:
            rules.append(_load_one(path))
        except RuleLoadError as e:
            logger.warning("skipping malformed rule file: %s", e)

    if not rules:
        logger.warning("no valid detection rules loaded from %s", rules_dir)
    else:
        logger.info("loaded %d detection rule(s) from %s", len(rules), rules_dir)
    return rules


_rules_cache: list[LoadedRule] | None = None


def get_loaded_rules(force_reload: bool = False) -> list[LoadedRule]:
    """Cached accessor (same pattern as mitre/loader.py's _lookup_cache) --
    rule files are loaded once and reused across requests instead of
    re-reading/re-validating them on every /ingest call.
    """
    global _rules_cache
    if _rules_cache is None or force_reload:
        _rules_cache = load_rules()
    return _rules_cache


if __name__ == "__main__":
    for rule in load_rules():
        print(f"{rule.rule_id}  [{rule.level}]  {rule.title}  (category={rule.category})")
