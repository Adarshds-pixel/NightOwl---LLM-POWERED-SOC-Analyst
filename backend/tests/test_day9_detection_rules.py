"""Day 9 verification (Pair 1): the rule set grows from 5 to 10 rules,
adding a 4th category (registry_event, Sysmon Event ID 13), and every
rule's technique_id/tactics parse correctly from its own `tags:` list
(rule_loader.py's new tag-extraction, not full MITRE-dataset validation --
that's still Day 11's job).
"""

from app.detection import rule_loader

EXPECTED_RULE_COUNT = 10
EXPECTED_CATEGORIES = {"process_creation", "network_connection", "file_event", "registry_event"}


def test_load_rules_returns_ten_rules():
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
