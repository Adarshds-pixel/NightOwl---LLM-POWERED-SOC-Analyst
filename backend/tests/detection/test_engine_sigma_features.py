"""The Sigma features the engine supports (and rejects) since the strict
rewrite: quantified conditions, wildcards, re / cidr / all / windash
modifiers, null values, EventID selections; plus the new sequence detectors."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.detection.engine import (
    ConditionSyntaxError,
    UnsupportedModifierError,
    _field_matches,
    evaluate_condition,
    evaluate_event,
    parse_field_key,
    validate_condition,
)
from app.detection.rule_loader import LoadedRule
from app.detection.sequences import detect_sequences
from app.schemas.event import NormalizedEvent

T0 = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)


def _event(event_id=1, channel="Microsoft-Windows-Sysmon/Operational", seconds=0, host="H", **data):
    return NormalizedEvent(
        host=host, timestamp=T0 + timedelta(seconds=seconds), event_id=event_id, channel=channel, event_data=data, raw={}
    )


def _rule(detections, condition, category="process_creation", channel="sysmon"):
    return LoadedRule(
        rule_id="r", title="R", level="medium", category=category, detections=detections,
        condition=condition, yaml_path="<t>", channel=channel,
    )


@pytest.mark.parametrize(
    "condition, results, expected",
    [
        ("1 of sel_*", {"sel_a": False, "sel_b": True, "filter": True}, True),
        ("all of sel_*", {"sel_a": False, "sel_b": True}, False),
        ("all of them", {"a": True, "b": True, "_meta": False}, True),
        ("1 of them and not filter", {"a": True, "filter": True}, False),
        ("any of sel*", {"sel1": False, "sel2": False}, False),
    ],
)
def test_quantified_conditions(condition, results, expected):
    assert evaluate_condition(condition, results) is expected


def test_condition_errors_surface_at_validation():
    with pytest.raises(ConditionSyntaxError):
        validate_condition("1 of nope_*", ["selection"])
    with pytest.raises(ConditionSyntaxError):
        validate_condition("selection and", ["selection"])


@pytest.mark.parametrize(
    "value, rule_value, modifier, flags, expected",
    [
        ("C:\\Tools\\procdump64.exe", "*\\procdump*.exe", None, set(), True),
        ("abc", "a?c", None, set(), True),
        ("a*c", "a\\*c", None, set(), True),
        ("abc", "a\\*c", None, set(), False),
        ("cmd /c whoami", ["cmd", "whoami"], "contains", {"all"}, True),
        ("cmd /c dir", ["cmd", "whoami"], "contains", {"all"}, False),
        ("certutil /urlcache -f", "-urlcache", "contains", {"windash"}, True),
        ("10.1.2.3", "10.0.0.0/8", "cidr", set(), True),
        ("8.8.8.8", "10.0.0.0/8", "cidr", set(), False),
        ("not-an-ip", "10.0.0.0/8", "cidr", set(), False),
        ("Invoke-Mimikatz", r"Invoke-\w+", "re", set(), True),
        ("", None, None, set(), True),
        (None, None, None, set(), True),
        ("x", None, None, set(), False),
    ],
)
def test_value_matching(value, rule_value, modifier, flags, expected):
    assert _field_matches(value, rule_value, modifier, frozenset(flags)) is expected


def test_unsupported_modifiers_raise():
    with pytest.raises(UnsupportedModifierError):
        parse_field_key("CommandLine|base64offset|contains")
    assert parse_field_key("CommandLine|contains|all") == ("CommandLine", "contains", frozenset({"all"}))


def test_eventid_selection_scopes_a_categoryless_rule():
    rule = _rule({"selection": {"EventID": 4625}}, "selection", category=None, channel="security")
    assert evaluate_event(_event(4625, channel="Security"), [rule])
    assert not evaluate_event(_event(4624, channel="Security"), [rule])


def _rows(events):
    return [(SimpleNamespace(id=i, host=e.host, timestamp=e.timestamp), e) for i, e in enumerate(events)]


def test_brute_force_sequence_fires_on_a_burst_only():
    burst = [_event(4625, "Security", s, IpAddress="10.9.9.9", TargetUserName="bob") for s in range(10)]
    assert any("Brute Force" in m.title for _a, m in detect_sequences(_rows(burst)))
    few = burst[:3]
    assert not any("Brute Force" in m.title for _a, m in detect_sequences(_rows(few)))


def test_mssql_failed_logons_count_toward_brute_force():
    events = [
        _event(18456, "Application", s, UnnamedEventData="<string>sa</string>\n<string> [CLIENT: 10.0.2.17]</string>")
        for s in range(9)
    ]
    assert any("Brute Force" in m.title for _a, m in detect_sequences(_rows(events)))


def test_group_self_add_and_bulk_addition():
    sid = "S-1-5-21-1-2-3-1158"
    self_add = _event(4728, "Security", 0, SubjectUserSid=sid, SubjectUserName="u", MemberSid=sid, TargetSid="S-1-5-21-1-2-3-1135")
    titles = {m.title for _a, m in detect_sequences(_rows([self_add]))}
    assert "Account Added Itself to a Security Group" in titles

    bulk = [
        _event(4728, "Security", i, SubjectUserSid=sid, SubjectUserName="u", MemberSid="S-1-5-21-1-2-3-1150",
               TargetSid=f"S-1-5-21-1-2-3-{1134 + i}")
        for i in range(6)
    ]
    assert "One Account Added Members to Many Security Groups in a Short Time" in {
        m.title for _a, m in detect_sequences(_rows(bulk))
    }


def test_machine_accounts_do_not_trigger_group_abuse():
    sid = "S-1-5-21-1-2-3-1000"
    events = [
        _event(4728, "Security", i, SubjectUserSid=sid, SubjectUserName="DC01$", MemberSid=sid, TargetSid=f"x-{i}")
        for i in range(6)
    ]
    assert detect_sequences(_rows(events)) == []


def test_mass_process_access_ignores_system_binaries():
    targets = [f"C:\\Windows\\System32\\p{i}.exe" for i in range(12)]
    attacker = [_event(10, seconds=0, SourceImage="D:\\m.exe", TargetImage=t, GrantedAccess="0x1410") for t in targets]
    assert any("Process Discovery" in m.title for _a, m in detect_sequences(_rows(attacker)))
    taskmgr = [_event(10, seconds=0, SourceImage="C:\\Windows\\System32\\Taskmgr.exe", TargetImage=t) for t in targets]
    assert detect_sequences(_rows(taskmgr)) == []
