"""Day 7 verification (Pair 1): detection/engine.py -- condition parsing,
field-modifier matching, category scoping, and end-to-end evaluate_event
against the real seed rule in detection/rules/.
"""

from datetime import datetime, timezone

import pytest

from app.detection import rule_loader
from app.detection.engine import (
    ConditionSyntaxError,
    covered_event_ids,
    evaluate_condition,
    evaluate_event,
)
from app.detection.rule_loader import LoadedRule
from app.schemas.event import NormalizedEvent


def _event(event_id=1, event_data=None, **overrides):
    fields = dict(
        host="WORKSTATION01",
        timestamp=datetime(2026, 8, 16, tzinfo=timezone.utc),
        event_id=event_id,
        # Default to a real Sysmon channel string since every seed rule is
        # `service: sysmon`-scoped -- pass channel=None (or another value)
        # via **overrides for a test that specifically needs otherwise.
        channel="Microsoft-Windows-Sysmon/Operational",
        raw={},
        event_data=event_data or {},
    )
    fields.update(overrides)
    return NormalizedEvent(**fields)


# -- condition parser ---------------------------------------------------

def test_evaluate_condition_bare_selection():
    assert evaluate_condition("selection", {"selection": True}) is True
    assert evaluate_condition("selection", {"selection": False}) is False


def test_evaluate_condition_and_or_not():
    results = {"a": True, "b": False}
    assert evaluate_condition("a and b", results) is False
    assert evaluate_condition("a or b", results) is True
    assert evaluate_condition("not b", results) is True
    assert evaluate_condition("a and not b", results) is True


def test_evaluate_condition_parentheses():
    results = {"a": False, "b": True, "c": False}
    assert evaluate_condition("(a or b) and not c", results) is True
    assert evaluate_condition("a and (b or c)", results) is False


def test_evaluate_condition_unknown_selection_raises():
    with pytest.raises(ConditionSyntaxError):
        evaluate_condition("nope", {"selection": True})


def test_evaluate_condition_empty_raises():
    with pytest.raises(ConditionSyntaxError):
        evaluate_condition("", {"selection": True})


# -- evaluate_event: field modifiers + category scoping ------------------

def _process_rule(selection, condition="selection", category="process_creation", channel=None):
    return LoadedRule(
        rule_id="test-rule",
        title="Test Rule",
        level="high",
        category=category,
        detections={"selection": selection},
        condition=condition,
        yaml_path="<test>",
        channel=channel,
    )


def test_evaluate_event_matches_contains_modifier():
    rule = _process_rule({"Image|contains": "powershell"})
    event = _event(event_id=1, event_data={"Image": "C:\\Windows\\System32\\powershell.exe"})

    matches = evaluate_event(event, [rule])

    assert len(matches) == 1
    assert matches[0].title == "Test Rule"


def test_evaluate_event_no_match_when_field_absent():
    rule = _process_rule({"Image|contains": "powershell"})
    event = _event(event_id=1, event_data={"CommandLine": "whoami"})

    assert evaluate_event(event, [rule]) == []


def test_evaluate_event_and_across_fields_in_one_selection():
    rule = _process_rule(
        {"Image|contains": "powershell", "CommandLine|contains": ["-enc", "-EncodedCommand"]}
    )
    only_image = _event(event_id=1, event_data={"Image": "powershell.exe"})
    both_fields = _event(
        event_id=1, event_data={"Image": "powershell.exe", "CommandLine": "-enc AAA"}
    )

    assert evaluate_event(only_image, [rule]) == []
    assert len(evaluate_event(both_fields, [rule])) == 1


def test_evaluate_event_skips_rule_when_category_does_not_match_event_id():
    rule = _process_rule({"Image|contains": "powershell"}, category="network_connection")
    event = _event(event_id=1, event_data={"Image": "powershell.exe"})

    assert evaluate_event(event, [rule]) == []


def test_evaluate_event_channel_mismatch_skips_even_when_event_id_matches_category():
    # process_access maps to both Sysmon 10 and Security 4656/4663 -- a
    # `channel="sysmon"` rule must not fire against a Security-channel
    # event just because 4663 is in that category's event-id set.
    rule = _process_rule({"ObjectName|endswith": "lsass.exe"}, category="process_access", channel="sysmon")
    event = _event(event_id=4663, event_data={"ObjectName": "C:\\Windows\\system32\\lsass.exe"}, channel="Security")

    assert evaluate_event(event, [rule]) == []


def test_evaluate_event_channel_match_fires():
    rule = _process_rule({"ObjectName|endswith": "lsass.exe"}, category="process_access", channel="security")
    event = _event(event_id=4663, event_data={"ObjectName": "C:\\Windows\\system32\\lsass.exe"}, channel="Security")

    assert len(evaluate_event(event, [rule])) == 1


def test_evaluate_event_no_channel_declared_matches_any_channel():
    rule = _process_rule({"Image|contains": "powershell"}, category="process_creation", channel=None)
    event = _event(event_id=1, event_data={"Image": "powershell.exe"}, channel="Security")

    assert len(evaluate_event(event, [rule])) == 1


# -- covered_event_ids ------------------------------------------------------


def test_covered_event_ids_empty_rules_returns_empty_set():
    assert covered_event_ids([]) == frozenset()


def test_covered_event_ids_excludes_unmapped_category():
    rule = _process_rule({"Image|contains": "x"}, category="not_a_real_category")
    assert covered_event_ids([rule]) == frozenset()


def test_covered_event_ids_keys_by_channel_not_just_event_id():
    """The regression this whole fix exists for: covered_event_ids() must
    return (channel, event_id) pairs, not a flat frozenset[int] that
    discards which channel a rule actually applies to. A Sysmon rule and
    a Security rule sharing the same category's event-id set produce
    distinct entries per channel -- coverage for one channel is never
    silently merged into or mistaken for coverage of the other, which is
    what a plain int-keyed set would have done."""
    sysmon_rule = _process_rule({"x": "y"}, category="process_access", channel="sysmon")
    security_rule = _process_rule({"x": "y"}, category="process_access", channel="security")

    sysmon_only_pairs = covered_event_ids([sysmon_rule])
    both_pairs = covered_event_ids([sysmon_rule, security_rule])

    assert ("sysmon", 10) in sysmon_only_pairs
    assert ("security", 10) not in sysmon_only_pairs  # no Security rule loaded yet
    assert ("sysmon", 10) in both_pairs
    assert ("security", 10) in both_pairs  # now covered once the Security rule loads too
    assert all(channel is not None for channel, _ in both_pairs)  # every entry carries its real channel


def test_evaluate_event_startswith_and_endswith():
    starts = _process_rule({"TargetFilename|startswith": "C:\\Windows\\Temp\\"}, category="file_event")
    ends = _process_rule({"TargetFilename|endswith": ".exe"}, category="file_event")

    match_event = _event(event_id=11, event_data={"TargetFilename": "C:\\Windows\\Temp\\payload.exe"})
    non_match_event = _event(event_id=11, event_data={"TargetFilename": "C:\\Users\\bob\\payload.dll"})

    assert len(evaluate_event(match_event, [starts])) == 1
    assert len(evaluate_event(match_event, [ends])) == 1
    assert evaluate_event(non_match_event, [starts]) == []
    assert evaluate_event(non_match_event, [ends]) == []


# -- end-to-end against the real seed rule file ---------------------------

def test_real_seed_rule_matches_encoded_powershell_event():
    rules = rule_loader.load_rules()
    event = _event(
        event_id=1,
        event_data={
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA",
        },
    )

    matches = evaluate_event(event, rules)

    assert any(m.title == "Suspicious Encoded PowerShell Command" for m in matches)


def test_real_seed_rule_does_not_match_benign_event():
    rules = rule_loader.load_rules()
    event = _event(
        event_id=1,
        event_data={"Image": "C:\\Windows\\System32\\notepad.exe", "CommandLine": "notepad.exe report.txt"},
    )

    matches = evaluate_event(event, rules)

    assert matches == []
