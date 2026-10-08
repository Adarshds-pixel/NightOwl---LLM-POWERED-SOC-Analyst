"""Detection engine: evaluates one NormalizedEvent against the rules
rule_loader.py loaded. pySigma validates rule structure at load time; matching
is done here (see rule_loader.py's docstring for why).

Supported Sigma semantics -- anything outside this set is REJECTED when the
rule loads (rule_loader._validate_rule_semantics), never silently skipped at
evaluation time:
  - `detection`: named selections, each a dict of `field[|modifiers]: value`
    (AND across fields) or a list of such dicts (OR across items); a value
    list is OR across values (AND with the `all` modifier); a `null` value
    matches a missing or empty field.
  - value modifiers: none (exact), `contains`, `startswith`, `endswith`,
    `re` (Python regex, case-sensitive), `cidr` (IP in network), plus the
    flags `all` and `windash` (`-x` also matches `/x` and the dash variants
    Windows command lines accept). All non-regex matching is
    case-insensitive.
  - wildcards: `*` and `?` inside exact/contains/startswith/endswith values,
    with a backslash before `*` or `?` for a literal character.
  - `condition`: `and` / `or` / `not` / parentheses over selection names,
    plus `1 of <pattern>`, `any of <pattern>`, `all of <pattern>` where the
    pattern is a selection name, a `prefix*` glob, or `them` (all selections
    not starting with `_`).

Rules are scoped by `logsource.category` -> event IDs (CATEGORY_TO_EVENT_ID)
and by `logsource.service` -> channel, so a rule never evaluates an event
type or channel it was not written for. Standard Sigma categories use the
standard Sysmon/PowerShell event-ID mapping.
"""

import fnmatch
import ipaddress
import logging
import re
from dataclasses import dataclass
from functools import lru_cache

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
    # Sysmon Event ID 6, "DriverLoaded" -- no rule ever mapped this before
    # (see known_abusable_driver_loaded.yml, which scopes it to a small,
    # named list of publicly documented BYOVD driver filenames).
    "driver_load": frozenset({6}),
    # Sysmon Event ID 7, "ImageLoaded" -- no rule used this category before
    # (see unmanaged_powershell_image_load.yml, which scopes it to the
    # PowerShell automation engine DLL loading into a non-PowerShell host).
    "image_load": frozenset({7}),
    "create_remote_thread": frozenset({8}),
    # 10 = Sysmon process access, 4656/4663 = Security object (incl.
    # process handle) access -- same channel-guard safety as above.
    "process_access": frozenset({10, 4656, 4663}),
    "file_event": frozenset({11}),
    # Sigma's registry categories (Sysmon 12 = key/value create or delete,
    # 13 = value set, 14 = rename). `registry_event` is Sigma's umbrella for
    # all three; it used to mean 13 only here, so key creations (EID 12)
    # under Run / IFEO were never evaluated.
    "registry_add": frozenset({12}),
    "registry_delete": frozenset({12}),
    "registry_set": frozenset({13}),
    "registry_rename": frozenset({14}),
    "registry_event": frozenset({12, 13, 14}),
    "process_termination": frozenset({5}),
    "raw_access_thread": frozenset({9}),
    "create_stream_hash": frozenset({15}),
    "pipe_created": frozenset({17, 18}),
    "pipe_event": frozenset({17, 18}),
    "process_tampering": frozenset({25}),
    # PowerShell/Operational -- Sigma names (4103 module, 4104 script block).
    "ps_module": frozenset({4103}),
    "ps_script": frozenset({4104}),
    "wmi_event": frozenset({19, 20, 21}),
    "dns_query": frozenset({22}),
    "file_delete": frozenset({23, 26}),
    # Security Event ID 1102, "The audit log was cleared" -- carries no
    # EventData at all on real samples, so its rule matches on event_id
    # alone (see security_audit_log_cleared.yml).
    "audit_log_cleared": frozenset({1102}),
    # Security Event ID 4662, "An operation was performed on an object" --
    # used here specifically for DCSync-style directory-replication rights
    # abuse (see dcsync_replication_rights.yml).
    "directory_service_access": frozenset({4662}),
    # Security Event ID 4799 ("a security-enabled local group membership
    # was enumerated") and 4798 ("a user's local group membership was
    # enumerated") -- both carry TargetUserName/CallerProcessName and are
    # scoped together since one rule's selection targets either shape (see
    # sensitive_group_account_enumeration.yml).
    "local_group_enumeration": frozenset({4798, 4799}),
    # Security Event ID 4624 ("an account was successfully logged on") --
    # scoped specifically to the loopback-tunneled RDP logon pattern (see
    # rdp_logon_via_loopback_tunnel.yml), not general logon monitoring.
    "rdp_tunneled_logon": frozenset({4624}),
    # Security Event ID 5145 ("a network share object was checked to see
    # whether client can be granted desired access") -- fires on every SMB
    # share access, so scoped narrowly to an executable-shaped write onto
    # an admin share (see admin_share_payload_write.yml), not blanket
    # presence.
    "admin_share_payload_write": frozenset({5145}),
    # Security Event ID 4732 ("a member was added to a security-enabled
    # local group") -- scoped to the well-known-low-privilege-account
    # pattern (see low_privilege_account_added_to_admins.yml), not blanket
    # group-membership monitoring.
    "local_group_membership_change": frozenset({4732}),
    # Security Event ID 4741 ("a computer account was created") -- the real
    # machine-account creation event (noPac / MachineAccountQuota abuse);
    # see computer_account_created.yml.
    "computer_account_created": frozenset({4741}),
    # Security Event ID 4720 ("a user account was created") -- scoped to a
    # user account given a machine-style trailing `$` to hide among computer
    # accounts; see user_account_disguised_as_computer.yml.
    "user_account_created": frozenset({4720}),
    # System Event ID 7045 ("a service was installed in the system").
    "service_installed_system": frozenset({7045}),
    # System Event ID 104 ("the System/other event log was cleared").
    "system_log_cleared": frozenset({104}),
    # Security Event ID 4771 ("Kerberos pre-authentication failed").
    "kerberos_preauth_failed": frozenset({4771}),
    # Security Event ID 4781 ("the name of an account was changed").
    "account_renamed": frozenset({4781}),
    # Security Event ID 4624 ("an account was successfully logged on").
    "logon_success": frozenset({4624}),
    # Security Event ID 4648 ("a logon was attempted using explicit credentials").
    "explicit_credential_logon": frozenset({4648}),
    # Security Event ID 4697 ("a service was installed in the system").
    "service_installed_security": frozenset({4697}),
    # Security Event ID 4698 ("a scheduled task was created") -- scoped to
    # the Hidden-flag pattern (see hidden_scheduled_task_created.yml), the
    # native-log complement to the existing Sysmon process-creation-based
    # scheduled-task rules.
    "scheduled_task_created_security": frozenset({4698}),
    # PowerShell/Operational Event ID 4104 ("Execute a Remote Command" --
    # Script Block Logging). Three separate rules share this category, one
    # per real-verified technique fingerprint (see each rule's own file):
    # LSASS dump via reflection, fake credential prompt, web download
    # cradle.
    "script_block_logging": frozenset({4104}),
    # Security Event ID 4719 ("system audit policy was changed") -- scoped
    # to the auditing-removed codes specifically (see
    # audit_policy_weakened.yml), not any audit policy change.
    "audit_policy_weakened": frozenset({4719}),
    # Security Event ID 5145 again, same event as admin_share_payload_write
    # above but a different real technique: connecting to the `winreg`
    # RPC endpoint over IPC$ (remote registry access), not a file write
    # onto C$/ADMIN$ (see remote_registry_access.yml). Two categories can
    # safely share one event ID -- each rule's own category determines
    # its own scoping, evaluate_event() never compares one rule's
    # category against another's.
    "remote_registry_access": frozenset({5145}),
    # Security Event ID 4697 ("a service was installed in the system") --
    # scoped to the kernel-driver-service-type pattern specifically (see
    # kernel_driver_service_installed.yml), not blanket 4697 monitoring:
    # no real benign-4697 sample exists in this project's corpus to bound
    # a broader rule's false-positive rate against.
    "kernel_driver_service_installed": frozenset({4697}),
    # Security Event ID 4728 ("a member was added to a security-enabled
    # global group") and 4756 (same for a universal group) -- scoped to
    # well-known privileged-group RID suffixes (see
    # sensitive_domain_group_membership_change.yml), not blanket
    # group-membership monitoring. Deliberately does not cover volume-only
    # or self-add patterns -- see the rule file's own description for why.
    "sensitive_domain_group_membership_change": frozenset({4728, 4756}),
    # Security Event ID 4661 ("a handle was requested to an object") --
    # scoped to SAM group-object handles specifically (see
    # sam_privileged_group_object_access.yml), not blanket 4661
    # monitoring: ProcessName is always lsass.exe regardless of the
    # caller on every real sample in this project's corpus, so
    # ObjectType + a well-known privileged-group RID suffix is the only
    # real discriminator.
    "sam_privileged_group_object_access": frozenset({4661}),
}

_BASE_MATCHERS = {None, "contains", "startswith", "endswith", "re", "cidr"}
_FLAG_MODIFIERS = {"all", "windash"}
# Kept for callers that still import it; the real check is parse_field_key().
_SUPPORTED_MODIFIERS = _BASE_MATCHERS
_TOKEN_RE = re.compile(r"\(|\)|[A-Za-z0-9_*]+")
_WINDASH_ALTERNATIVES = ("-", "/", "\u2013", "\u2014", "\u2015")


class UnsupportedModifierError(ValueError):
    pass


@lru_cache(maxsize=4096)
def parse_field_key(key: str) -> tuple[str, str | None, frozenset[str]]:
    """`Field|mod|mod` -> (field, base matcher, flags). Raises
    UnsupportedModifierError for anything this engine cannot evaluate."""
    field, *mods = key.split("|")
    base: str | None = None
    flags: set[str] = set()
    for mod in (m.strip().lower() for m in mods):
        if mod in _FLAG_MODIFIERS:
            flags.add(mod)
        elif mod in _BASE_MATCHERS and base is None:
            base = mod
        else:
            raise UnsupportedModifierError(f"unsupported modifier {mod!r} in {key!r}")
    if base in ("re", "cidr") and "windash" in flags:
        raise UnsupportedModifierError(f"windash cannot combine with {base} in {key!r}")
    return field, base, frozenset(flags)


def _has_wildcard(value: str) -> bool:
    return re.search(r"(?<!\\)[*?]", value) is not None


@lru_cache(maxsize=8192)
def _wildcard_regex(value: str, base: str | None) -> re.Pattern:
    parts: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?":
            parts.append(re.escape(value[i + 1]))
            i += 2
            continue
        parts.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        i += 1
    body = "".join(parts)
    if base is None:
        body = f"^{body}$"
    elif base == "startswith":
        body = f"^{body}"
    elif base == "endswith":
        body = f"{body}$"
    return re.compile(body, re.IGNORECASE | re.DOTALL)


def _windash_variants(value: str) -> list[str]:
    if not re.search(r"(^|\s)-", value):
        return [value]
    return [re.sub(r"(^|\s)-", lambda m, d=d: m.group(1) + d, value) for d in _WINDASH_ALTERNATIVES]


def _match_one(event_str: str, candidate: object, base: str | None) -> bool:
    if base == "re":
        try:
            return re.search(str(candidate), event_str) is not None
        except re.error:
            return False
    if base == "cidr":
        try:
            return ipaddress.ip_address(event_str.strip()) in ipaddress.ip_network(str(candidate), strict=False)
        except ValueError:
            return False
    candidate_str = str(candidate)
    # Escaped wildcards (\* \?) also go through the pattern path, which is
    # what turns them back into literal * / ? characters.
    if _has_wildcard(candidate_str) or "\\*" in candidate_str or "\\?" in candidate_str:
        return _wildcard_regex(candidate_str, base).search(event_str) is not None
    event_l, cand_l = event_str.lower(), candidate_str.lower()
    if base == "contains":
        return cand_l in event_l
    if base == "startswith":
        return event_l.startswith(cand_l)
    if base == "endswith":
        return event_l.endswith(cand_l)
    return event_l == cand_l


def _field_matches(event_value: object, rule_value: object, modifier: str | None, flags: frozenset[str] = frozenset()) -> bool:
    candidates = rule_value if isinstance(rule_value, list) else [rule_value]

    # Sigma `field: null` -- the field is absent or empty.
    if any(c is None for c in candidates):
        if event_value is None or event_value == "":
            return True
        candidates = [c for c in candidates if c is not None]
        if not candidates:
            return False
    if event_value is None:
        return False
    if modifier not in _BASE_MATCHERS:
        return False

    # Element-wise for list-valued fields, never the list's repr.
    if isinstance(event_value, (list, tuple)):
        return any(_field_matches(element, rule_value, modifier, flags) for element in event_value)

    event_str = str(event_value)
    if "windash" in flags:
        expanded: list[object] = []
        for candidate in candidates:
            expanded.append(_windash_variants(str(candidate)))
        results = [any(_match_one(event_str, v, modifier) for v in group) for group in expanded]
    else:
        results = [_match_one(event_str, candidate, modifier) for candidate in candidates]
    return all(results) if "all" in flags else any(results)


def _selection_matches(match_dict: dict[str, object], selection_body: object) -> bool:
    if isinstance(selection_body, list):
        return any(_selection_matches(match_dict, item) for item in selection_body)
    if not isinstance(selection_body, dict):
        logger.warning("unsupported selection shape %r", type(selection_body))
        return False

    for key, rule_value in selection_body.items():
        field, base, flags = parse_field_key(key)
        if not _field_matches(match_dict.get(field), rule_value, base, flags):
            return False
    return True


def _build_match_dict(event: NormalizedEvent) -> dict[str, object]:
    """NightOwl's normalized fields, the raw EventData fields (Image,
    CommandLine, DestinationIp, ...) and the standard Sigma `EventID` /
    `Channel` names, so rules can target any of these vocabularies."""
    # Built field by field rather than via model_dump(): this runs for every
    # event a rule could apply to, and model_dump was the dominant cost on
    # large captures.
    return {
        "host": event.host,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "event_id": event.event_id,
        "channel": event.channel,
        "event_record_id": event.event_record_id,
        "process": event.process,
        "parent_process": event.parent_process,
        "command_line": event.command_line,
        "user": event.user,
        "protocol": event.protocol,
        "source_ip": event.source_ip,
        "source_port": event.source_port,
        "destination_ip": event.destination_ip,
        "destination_port": event.destination_port,
        "target_filename": event.target_filename,
        "EventID": event.event_id,
        "Channel": event.channel,
        **event.event_data,
    }


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

    def _selection_names(self, pattern: str) -> list[str]:
        if pattern == "them":
            return [n for n in self.results if not n.startswith("_")]
        names = [n for n in self.results if fnmatch.fnmatchcase(n, pattern)]
        if not names:
            raise ConditionSyntaxError(f"'of' pattern {pattern!r} matches no selection")
        return names

    def _parse_atom(self) -> bool:
        tok = self._advance()
        if tok in ("1", "any", "all") and self._peek() == "of":
            self._advance()
            target = self._advance()
            if target is None or target in ("(", ")", "and", "or", "not"):
                raise ConditionSyntaxError(f"'{tok} of' needs a selection name, pattern or 'them'")
            values = [self.results[name] for name in self._selection_names(target)]
            return all(values) if tok == "all" else any(values)
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


def validate_condition(condition: str, selection_names) -> None:
    """Parse `condition` once against the rule's real selection names --
    raises ConditionSyntaxError for anything evaluate_condition() could not
    evaluate. Called at rule load time so a bad condition is rejected up
    front, not skipped with a warning on every event."""
    names = list(selection_names)
    evaluate_condition(condition, {name: False for name in names})
    evaluate_condition(condition, {name: True for name in names})


def evaluate_condition(condition: str, selection_results: dict[str, bool]) -> bool:
    tokens = _TOKEN_RE.findall(condition)
    if not tokens:
        raise ConditionSyntaxError("empty condition")
    return _ConditionParser(tokens, selection_results).parse()


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
        if rule.category:
            event_ids = CATEGORY_TO_EVENT_ID.get(rule.category, frozenset())
        else:
            # A rule scoped by an explicit `EventID` selection instead of a
            # category (the loader accepts both) covers exactly those ids.
            event_ids = explicit_event_ids(rule.detections)
        pairs.update((rule.channel, event_id) for event_id in event_ids)
    return frozenset(pairs)


def explicit_event_ids(detections: dict[str, object]) -> frozenset[int]:
    """Every integer EventID named in a rule's selections."""
    found: set[int] = set()

    def walk(body: object) -> None:
        if isinstance(body, list):
            for item in body:
                walk(item)
        elif isinstance(body, dict):
            for key, value in body.items():
                if isinstance(key, str) and key.split("|")[0] in ("EventID", "event_id"):
                    for item in value if isinstance(value, list) else [value]:
                        if isinstance(item, int) and not isinstance(item, bool):
                            found.add(item)
                else:
                    walk(value)

    for body in detections.values():
        walk(body)
    return frozenset(found)


def evaluate_event(event: NormalizedEvent, rules: list[LoadedRule]) -> list[RuleMatch]:
    # Built lazily: most events (e.g. routine Security logons) are in no
    # rule's scope, and building the field dict for them was wasted work.
    match_dict: dict[str, object] | None = None
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

        if match_dict is None:
            match_dict = _build_match_dict(event)
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
