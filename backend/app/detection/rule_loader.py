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

Day 11 adds MITRE technique validation: each rule's parsed `technique_id`
(Day 9's `_parse_tags`) is checked against the real MITRE ATT&CK dataset
via `mitre/validator.py`. Unlike a malformed rule file, an unknown/
deprecated/revoked technique tag is warn-only -- the rule still loads and
still detects, since the detection logic itself (selections/condition) is
unaffected by a bad MITRE tag; only the tag is untrustworthy.
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

from app.ingestion.normalizer import canonical_channel
from app.mitre.validator import validate_technique_id

logger = logging.getLogger(__name__)

RULES_DIR = Path(__file__).resolve().parent / "rules"

_TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


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
    # Parsed from the rule's own `tags:` list (Day 9), e.g. `attack.t1547.001`
    # -> technique_id, `attack.persistence` -> a tactic. Defaulted so every
    # existing LoadedRule(...) construction in Day 7/8 tests keeps working
    # unchanged. This is tag *extraction*, not MITRE-dataset validation --
    # that stays Day 11's job (mitre/validator.py).
    technique_id: str | None = None
    # Parsed from `logsource.service` (Sigma-standard field), reduced to a
    # canonical token ("sysmon", "security") via normalizer.canonical_channel
    # -- see engine.py's evaluate_event() scoping guard. None means the rule
    # declares no channel constraint (matches any channel that satisfies its
    # category's event-ID set); every current rule declares one after the
    # Day-N channel-scoping pass, so this is a safety default, not a path
    # any real rule relies on.
    channel: str | None = None
    tactics: list[str] = field(default_factory=list)
    # Descriptive metadata straight off the YAML front matter. Defaulted
    # like technique_id/tactics above so existing LoadedRule(...) calls in
    # tests stay valid; carried purely so `GET /rules` can show an analyst
    # what a rule is for without shipping the whole file to the browser.
    description: str = ""
    author: str = ""
    date: str = ""
    references: list[str] = field(default_factory=list)
    status: str = ""


def _validate_category(path: Path, category: str | None) -> None:
    """Warns when a rule's `logsource.category` isn't one engine.py knows how
    to scope to an event ID. Without this, a typo'd or unmapped category
    silently means `expected_event_ids is None`, and evaluate_event() runs
    the rule against *every* event instead of skipping it -- warn-only,
    matching this loader's existing tolerance policy, since the rule may
    still be intentionally unscoped.
    """
    if category is None:
        return
    # Deferred import: engine.py imports LoadedRule from this module, so a
    # top-level import here would be circular.
    from app.detection.engine import CATEGORY_TO_EVENT_ID

    if category not in CATEGORY_TO_EVENT_ID:
        logger.warning("%s: logsource.category %r is not scoped to any event ID in engine.py "
                        "-- this rule will run unscoped against every event", path, category)


def _parse_channel(path: Path, service: object) -> str | None:
    """Reduces `logsource.service` to the canonical token engine.py's
    scoping guard compares against. Warn-only (not RuleLoadError) on an
    unrecognized value -- matching this loader's existing tolerance
    policy -- since the rule still loads and detects; only its channel
    scoping is untrustworthy.
    """
    if not isinstance(service, str) or not service:
        return None
    token = canonical_channel(service)
    if token is None:
        logger.warning("%s: logsource.service %r is not a recognized channel -- "
                        "this rule will run unscoped by channel", path, service)
    return token


def _validate_technique(path: Path, technique_id: str | None) -> None:
    """Validates a rule's parsed technique_id against the real MITRE
    ATT&CK dataset (Day 11) via mitre/validator.py (Pair 2's Day 6
    scaffold). Warn-only, matching the loader's existing "log + keep
    going" tolerance policy: an unknown/deprecated/revoked technique tag
    is a rule-authoring problem worth surfacing, not a reason to drop an
    otherwise-valid detection rule from the running rule set.
    """
    if technique_id is None:
        return
    result = validate_technique_id(technique_id)
    if not result.is_valid:
        logger.warning("%s: tagged with unknown MITRE technique id %r", path, technique_id)
    elif result.is_revoked:
        logger.warning("%s: tagged with revoked MITRE technique id %r", path, technique_id)
    elif result.is_deprecated:
        logger.warning("%s: tagged with deprecated MITRE technique id %r", path, technique_id)


def _parse_tags(tags: object) -> tuple[str | None, list[str]]:
    """Splits a rule's raw `tags:` list into (technique_id, tactics).
    Tags are plain strings from `yaml.safe_load`, e.g. ["attack.execution",
    "attack.t1059.001"] -- the technique-id-shaped tag is picked out via
    regex, everything else under the `attack.` namespace is treated as a
    tactic name.
    """
    if not isinstance(tags, list):
        return None, []

    technique_id: str | None = None
    tactics: list[str] = []
    for tag in tags:
        if not isinstance(tag, str):
            continue
        match = _TECHNIQUE_TAG_RE.match(tag)
        if match:
            technique_id = match.group(1).upper()
        elif tag.lower().startswith("attack."):
            tactics.append(tag[len("attack."):].lower())
    return technique_id, tactics


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
    technique_id, tactics = _parse_tags(raw.get("tags"))
    _validate_technique(path, technique_id)
    _validate_category(path, logsource.get("category"))
    channel = _parse_channel(path, logsource.get("service"))

    return LoadedRule(
        rule_id=str(sigma_rule.id) if sigma_rule.id else path.stem,
        title=sigma_rule.title,
        level=sigma_rule.level.name.lower() if sigma_rule.level else "unknown",
        category=logsource.get("category"),
        detections=detections,
        condition=condition,
        yaml_path=str(path),
        technique_id=technique_id,
        channel=channel,
        tactics=tactics,
        description=str(raw.get("description") or "").strip(),
        author=str(raw.get("author") or "").strip(),
        date=str(raw.get("date") or "").strip(),
        references=[str(r) for r in (raw.get("references") or []) if isinstance(r, (str, int))],
        status=str(raw.get("status") or "").strip(),
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
