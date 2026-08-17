"""Detection engine v1 (Day 7): evaluates one NormalizedEvent against the
rules rule_loader.py loaded, without going through pySigma's backends (see
rule_loader.py's docstring / docs/decisions.md for why).

Supported subset of Sigma semantics (v1 -- documented limitations, not
oversights):
  - a rule's `detection` block is one or more named selections, each a dict
    of `field[|modifier]: value` (AND across fields in one selection) or a
    list of such dicts (OR across the list items)
  - field modifiers: none (exact match), `contains`, `startswith`,
    `endswith` -- all case-insensitive. `|re` and glob `*` wildcards are
    not implemented yet.
  - `condition` is a single boolean expression over selection names using
    `and` / `or` / `not` / parentheses. Sigma's `1 of` / `all of` shorthand
    is not implemented yet.

Rules are additionally scoped by `logsource.category` -> Sysmon event ID
(CATEGORY_TO_EVENT_ID), so a network-connection rule never runs against a
process-creation event.
"""

import logging
import re
from dataclasses import dataclass

from app.detection.rule_loader import LoadedRule
from app.schemas.event import NormalizedEvent
from app.services import severity_service

logger = logging.getLogger(__name__)

CATEGORY_TO_EVENT_ID: dict[str, int] = {
    "process_creation": 1,
    "network_connection": 3,
    "file_event": 11,
    # Sysmon Event ID 13, "RegistryEvent (Value Set)" -- Day 9. Only
    # value-set is covered (v1 scope), not key create/delete (12) or
    # rename (14); see docs/decisions.md.
    "registry_event": 13,
}

_SUPPORTED_MODIFIERS = {None, "contains", "startswith", "endswith"}
_TOKEN_RE = re.compile(r"\(|\)|[A-Za-z_][A-Za-z0-9_]*")


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    title: str
    # Final severity after severity_service.compute_severity (base Sigma
    # level + tactic weight, Day 10) -- not the raw, unweighted rule level.
    level: str
    technique_id: str | None = None


class ConditionSyntaxError(Exception):
    pass


class _ConditionParser:
    """Tiny recursive-descent parser/evaluator for `and`/`or`/`not`/`()`
    over selection names -- deliberately not `eval()` (never run untrusted
    rule-file text as Python), and small enough to unit test exhaustively.
    """

    def __init__(self, tokens: list[str], results: dict[str, bool]):
        self.tokens = tokens
        self.results = results
        self.pos = 0

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _advance(self) -> str | None:
        tok = self._peek()
        self.pos += 1
        return tok

    def parse(self) -> bool:
        value = self._parse_or()
        if self._peek() is not None:
            raise ConditionSyntaxError(f"unexpected trailing token {self._peek()!r}")
        return value

    def _parse_or(self) -> bool:
        value = self._parse_and()
        while self._peek() == "or":
            self._advance()
            rhs = self._parse_and()  # always parse to keep token position correct
            value = value or rhs
        return value

    def _parse_and(self) -> bool:
        value = self._parse_not()
        while self._peek() == "and":
            self._advance()
            rhs = self._parse_not()
            value = value and rhs
        return value

    def _parse_not(self) -> bool:
        if self._peek() == "not":
            self._advance()
            return not self._parse_not()
        return self._parse_atom()

    def _parse_atom(self) -> bool:
        tok = self._advance()
        if tok == "(":
            value = self._parse_or()
            if self._advance() != ")":
                raise ConditionSyntaxError("missing closing ')'")
            return value
        if tok is None:
            raise ConditionSyntaxError("unexpected end of condition")
        if tok in ("and", "or", "not", ")"):
            raise ConditionSyntaxError(f"unexpected token {tok!r}")
        if tok not in self.results:
            raise ConditionSyntaxError(f"condition references unknown selection {tok!r}")
        return self.results[tok]


def evaluate_condition(condition: str, selection_results: dict[str, bool]) -> bool:
    tokens = _TOKEN_RE.findall(condition)
    if not tokens:
        raise ConditionSyntaxError("empty condition")
    return _ConditionParser(tokens, selection_results).parse()


def _field_matches(event_value: object, rule_value: object, modifier: str | None) -> bool:
    if event_value is None:
        return False
    if modifier not in _SUPPORTED_MODIFIERS:
        logger.warning("unsupported sigma modifier %r (v1 supports contains/startswith/endswith)", modifier)
        return False

    candidates = rule_value if isinstance(rule_value, list) else [rule_value]
    event_str = str(event_value).lower()
    for candidate in candidates:
        candidate_str = str(candidate).lower()
        if modifier == "contains" and candidate_str in event_str:
            return True
        if modifier == "startswith" and event_str.startswith(candidate_str):
            return True
        if modifier == "endswith" and event_str.endswith(candidate_str):
            return True
        if modifier is None and event_str == candidate_str:
            return True
    return False


def _selection_matches(match_dict: dict[str, object], selection_body: object) -> bool:
    if isinstance(selection_body, list):
        return any(_selection_matches(match_dict, item) for item in selection_body)
    if not isinstance(selection_body, dict):
        logger.warning("unsupported selection shape %r (v1 supports dict/list-of-dict only)", type(selection_body))
        return False

    for key, rule_value in selection_body.items():
        field, _, modifier = key.partition("|")
        if not _field_matches(match_dict.get(field), rule_value, modifier or None):
            return False
    return True


def _build_match_dict(event: NormalizedEvent) -> dict[str, object]:
    """Merges NightOwl's normalized fields with the raw Sysmon EventData
    fields (Image, CommandLine, DestinationIp, ...) so rules can target
    either vocabulary -- see schemas/event.py's `event_data` field.
    """
    return {**event.model_dump(mode="json", exclude={"event_data"}), **event.event_data}


def evaluate_event(event: NormalizedEvent, rules: list[LoadedRule]) -> list[RuleMatch]:
    match_dict = _build_match_dict(event)
    matches: list[RuleMatch] = []

    for rule in rules:
        expected_event_id = CATEGORY_TO_EVENT_ID.get(rule.category) if rule.category else None
        if expected_event_id is not None and expected_event_id != event.event_id:
            continue

        selection_results = {name: _selection_matches(match_dict, body) for name, body in rule.detections.items()}
        try:
            matched = evaluate_condition(rule.condition, selection_results)
        except ConditionSyntaxError as e:
            logger.warning("skipping rule %s (%s): %s", rule.rule_id, rule.title, e)
            continue

        if matched:
            final_level = severity_service.compute_severity(rule.level, rule.tactics)
            matches.append(
                RuleMatch(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    level=final_level,
                    technique_id=rule.technique_id,
                )
            )

    return matches
