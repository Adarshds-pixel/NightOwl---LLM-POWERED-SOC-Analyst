"""Day 7 verification (Pair 1): detection/rule_loader.py loads + validates
Sigma rule YAML files, tolerating malformed ones (logged + skipped, not a
crash) the same way the ingest pipeline tolerates malformed records.

Day 9 verification (Pair 1): the rule set grows from 5 to 10 rules, adding
a 4th category (registry_event, Sysmon Event ID 13), and every rule's
technique_id/tactics parse correctly from its own `tags:` list
(rule_loader.py's new tag-extraction, not full MITRE-dataset validation --
that's still Day 11's job).

Day 11 verification (Pair 1): a rule's parsed technique_id is checked
against the real MITRE ATT&CK dataset (mitre/validator.py); unknown/
deprecated/revoked tags are warn-only -- the rule still loads (see
rule_loader.py's module docstring for why).
"""

import logging

from app.detection import rule_loader
from app.mitre.validator import TechniqueValidationResult

VALID_RULE = """
title: Test Rule
id: 11111111-1111-1111-1111-111111111111
status: experimental
logsource:
  category: process_creation
detection:
  selection:
    Image|contains: powershell
  condition: selection
level: high
"""

MALFORMED_RULE = """
title: Missing Detection Block
logsource:
  category: process_creation
"""

EXPECTED_RULE_COUNT = 15
EXPECTED_CATEGORIES = {"process_creation", "network_connection", "file_event", "registry_event"}


# -- Day 7: loading/validation/caching -----------------------------------

def test_load_rules_loads_valid_rule(tmp_path):
    (tmp_path / "valid.yml").write_text(VALID_RULE, encoding="utf-8")

    rules = rule_loader.load_rules(tmp_path)

    assert len(rules) == 1
    rule = rules[0]
    assert rule.title == "Test Rule"
    assert rule.category == "process_creation"
    assert rule.level == "high"
    assert rule.condition == "selection"
    assert "selection" in rule.detections


def test_load_rules_skips_malformed_and_keeps_valid(tmp_path):
    (tmp_path / "valid.yml").write_text(VALID_RULE, encoding="utf-8")
    (tmp_path / "bad.yml").write_text(MALFORMED_RULE, encoding="utf-8")

    rules = rule_loader.load_rules(tmp_path)

    assert len(rules) == 1
    assert rules[0].title == "Test Rule"


def test_load_rules_missing_directory_returns_empty(tmp_path):
    rules = rule_loader.load_rules(tmp_path / "does_not_exist")

    assert rules == []


def test_load_rules_empty_directory_returns_empty(tmp_path):
    rules = rule_loader.load_rules(tmp_path)

    assert rules == []


def test_get_loaded_rules_caches_across_calls(monkeypatch):
    rule_loader._rules_cache = None
    calls = []

    def fake_load_rules(rules_dir=rule_loader.RULES_DIR):
        calls.append(1)
        return ["fake-rule"]

    monkeypatch.setattr(rule_loader, "load_rules", fake_load_rules)

    first = rule_loader.get_loaded_rules()
    second = rule_loader.get_loaded_rules()

    assert first == ["fake-rule"]
    assert second == ["fake-rule"]
    assert len(calls) == 1

    rule_loader.get_loaded_rules(force_reload=True)
    assert len(calls) == 2

    rule_loader._rules_cache = None


def test_seed_rule_directory_loads_at_least_one_real_rule():
    rules = rule_loader.load_rules()

    assert len(rules) >= 1
    assert any(r.title == "Suspicious Encoded PowerShell Command" for r in rules)


# -- Day 9/12: rule count/category growth + tag-parsing --------------------

def test_load_rules_returns_fifteen_rules():
    rules = rule_loader.load_rules()
    assert len(rules) == EXPECTED_RULE_COUNT


def test_load_rules_covers_four_categories_including_registry():
    rules = rule_loader.load_rules()
    categories = {r.category for r in rules}
    assert categories == EXPECTED_CATEGORIES


def test_every_rule_has_a_technique_id_parsed_from_tags():
    rules = rule_loader.load_rules()
    missing = [r.title for r in rules if not r.technique_id]
    assert missing == []


def test_every_rule_has_at_least_one_tactic_parsed_from_tags():
    rules = rule_loader.load_rules()
    missing = [r.title for r in rules if not r.tactics]
    assert missing == []


def test_registry_run_key_rule_technique_id_and_tactics():
    rules = rule_loader.load_rules()
    rule = next(r for r in rules if r.title == "Registry Run Key Persistence")
    assert rule.technique_id == "T1547.001"
    assert set(rule.tactics) == {"persistence", "privilege_escalation"}


def test_scheduled_task_schtasks_rule_technique_id():
    rules = rule_loader.load_rules()
    rule = next(r for r in rules if r.title == "Scheduled Task Creation via schtasks.exe")
    assert rule.technique_id == "T1053.005"
    assert rule.category == "process_creation"


def test_mshta_rule_technique_id_and_tactics():
    rules = rule_loader.load_rules()
    rule = next(r for r in rules if r.title == "Suspicious Mshta Execution")
    assert rule.technique_id == "T1218.005"
    assert set(rule.tactics) == {"defense_evasion", "execution"}


# -- Day 11: MITRE technique validation -----------------------------------

def _rule_with_technique_tag(tag: str) -> str:
    return f"""
title: Test Rule With Technique Tag
id: 22222222-2222-2222-2222-222222222222
status: experimental
tags:
  - {tag}
logsource:
  category: process_creation
detection:
  selection:
    Image|contains: powershell
  condition: selection
level: high
"""


def test_valid_technique_id_loads_without_warning(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(
        rule_loader,
        "validate_technique_id",
        lambda tid: TechniqueValidationResult(technique_id=tid, is_valid=True),
    )
    (tmp_path / "valid_tech.yml").write_text(_rule_with_technique_tag("attack.t1059.001"), encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        rules = rule_loader.load_rules(tmp_path)

    assert len(rules) == 1
    assert rules[0].technique_id == "T1059.001"
    assert caplog.records == []


def test_unknown_technique_id_warns_but_rule_still_loads(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(
        rule_loader,
        "validate_technique_id",
        lambda tid: TechniqueValidationResult(technique_id=tid, is_valid=False),
    )
    (tmp_path / "unknown_tech.yml").write_text(_rule_with_technique_tag("attack.t9999.999"), encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        rules = rule_loader.load_rules(tmp_path)

    assert len(rules) == 1
    assert "unknown MITRE technique id" in caplog.text
    assert "T9999.999" in caplog.text


def test_deprecated_technique_id_warns_but_rule_still_loads(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(
        rule_loader,
        "validate_technique_id",
        lambda tid: TechniqueValidationResult(technique_id=tid, is_valid=True, is_deprecated=True),
    )
    (tmp_path / "deprecated_tech.yml").write_text(_rule_with_technique_tag("attack.t1086"), encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        rules = rule_loader.load_rules(tmp_path)

    assert len(rules) == 1
    assert "deprecated MITRE technique id" in caplog.text


def test_revoked_technique_id_warns_but_rule_still_loads(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(
        rule_loader,
        "validate_technique_id",
        lambda tid: TechniqueValidationResult(technique_id=tid, is_valid=True, is_revoked=True),
    )
    (tmp_path / "revoked_tech.yml").write_text(_rule_with_technique_tag("attack.t1000"), encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        rules = rule_loader.load_rules(tmp_path)

    assert len(rules) == 1
    assert "revoked MITRE technique id" in caplog.text


def test_real_seed_rules_all_have_valid_technique_ids():
    """The 10 real rule files should tag only real, non-deprecated,
    non-revoked technique ids -- a failure here means a rule's tags: list
    has a typo, not a validator bug."""
    rules = rule_loader.load_rules()
    for rule in rules:
        result = rule_loader.validate_technique_id(rule.technique_id)
        assert result.is_valid, f"{rule.title}: unknown technique id {rule.technique_id!r}"
        assert not result.is_deprecated, f"{rule.title}: deprecated technique id {rule.technique_id!r}"
        assert not result.is_revoked, f"{rule.title}: revoked technique id {rule.technique_id!r}"
