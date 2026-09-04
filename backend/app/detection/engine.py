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
from app.ingestion.normalizer import canonical_channel
from app.schemas.event import NormalizedEvent
from app.services import severity_service

logger = logging.getLogger(__name__)

CATEGORY_TO_EVENT_ID: dict[str, frozenset[int]] = {
    # 1 = Sysmon process creation, 4688 = Security process creation. Safe to
    # list side by side: evaluate_event()'s channel guard means a
    # `service: sysmon` rule never sees a 4688 event and vice versa, even
    # though both IDs sit in this one category's set.
    "process_creation": frozenset({1, 4688}),
    "file_change": frozenset({2}),
    "network_connection": frozenset({3}),
    "image_load": frozenset({7}),
    "create_remote_thread": frozenset({8}),
    # 10 = Sysmon process access, 4656/4663 = Security object (incl.
    # process handle) access -- same channel-guard safety as above.
    "process_access": frozenset({10, 4656, 4663}),
    "file_event": frozenset({11}),
    "registry_add": frozenset({12}),
    # Sysmon Event ID 13, "RegistryEvent (Value Set)" -- Day 9.
    "registry_event": frozenset({13}),
    "registry_rename": frozenset({14}),
    "pipe_event": frozenset({17, 18}),
    "wmi_event": frozenset({19, 20, 21}),
    "dns_query": frozenset({22}),
    "file_delete": frozenset({23}),
    # Security Event ID 1102, "The audit log was cleared" -- carries no
    # EventData at all on real samples, so its rule matches on event_id
    # alone (see security_audit_log_cleared.yml).
    "audit_log_cleared": frozenset({1102}),
    # Security Event ID 4662, "An operation was performed on an object" --
    # used here specifically for DCSync-style directory-replication rights
    # abuse (see dcsync_replication_rights.yml).
    "directory_service_access": frozenset({4662}),
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
    # The 1-5 rank `level` is derived from (severity_service.compute_severity_score),
    # kept alongside the label so callers can persist/display it instead of
    # only ever the collapsed label.
    score: int
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


def covered_event_ids(rules: list[LoadedRule]) -> frozenset[tuple[str | None, int]]:
    """The (rule.channel, event_id) pairs at least one *currently loaded*
    rule actually covers -- computed from `rules`, not the static
    CATEGORY_TO_EVENT_ID table, so a category with zero loaded rules
    correctly reads as uncovered and this never goes stale as rules are
    added/removed.

    Keyed by channel, not just event_id: Windows event IDs are not
    globally unique across providers (Sysmon vs. Security vs. others can
    reuse the same small integer for unrelated things), so a flat
    frozenset[int] would silently misreport coverage the moment a second
    channel's event IDs entered the mix. `rule.channel is None` (a rule
    declaring no channel constraint) is recorded as covering `(None, id)`
    -- an event only matches that pair if its own canonical channel is
    also unrecognized/None, not "any channel", keeping this set honest.
    """
    pairs: set[tuple[str | None, int]] = set()
    for rule in rules:
        if not rule.category:
            continue
        event_ids = CATEGORY_TO_EVENT_ID.get(rule.category)
        if not event_ids:
            continue
        pairs.update((rule.channel, event_id) for event_id in event_ids)
    return frozenset(pairs)


def evaluate_event(event: NormalizedEvent, rules: list[LoadedRule]) -> list[RuleMatch]:
    match_dict = _build_match_dict(event)
    matches: list[RuleMatch] = []
    event_channel = canonical_channel(event.channel)

    for rule in rules:
        expected_event_ids = CATEGORY_TO_EVENT_ID.get(rule.category) if rule.category else None
        if expected_event_ids is not None and event.event_id not in expected_event_ids:
            continue
        # A rule scoped to a channel must never evaluate against a
        # different channel's event, even when its event_id happens to be
        # in the category's set (e.g. Sysmon 1 vs. Security 4688 both
        # under `process_creation`) -- see covered_event_ids()'s docstring.
        if rule.channel is not None and rule.channel != event_channel:
            continue

        selection_results = {name: _selection_matches(match_dict, body) for name, body in rule.detections.items()}
        try:
            matched = evaluate_condition(rule.condition, selection_results)
        except ConditionSyntaxError as e:
            logger.warning("skipping rule %s (%s): %s", rule.rule_id, rule.title, e)
            continue

        if matched:
            final_level = severity_service.compute_severity(rule.level, rule.tactics)
            final_score = severity_service.compute_severity_score(rule.level, rule.tactics)
            matches.append(
                RuleMatch(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    level=final_level,
                    score=final_score,
                    technique_id=rule.technique_id,
                )
            )

    return matches
