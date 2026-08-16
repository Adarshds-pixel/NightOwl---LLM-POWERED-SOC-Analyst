"""Day 7 verification (Pair 1): detection/rule_loader.py loads + validates
Sigma rule YAML files, tolerating malformed ones (logged + skipped, not a
crash) the same way the ingest pipeline tolerates malformed records.
"""

from app.detection import rule_loader

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
