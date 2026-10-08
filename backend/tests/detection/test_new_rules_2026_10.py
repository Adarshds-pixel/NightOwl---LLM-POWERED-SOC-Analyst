"""Rules added after the 2026-10-08 upload audit, each checked against the real
content that motivated it and against a benign look-alike.

(title, channel, event_id, matching event_data, benign look-alike event_data)
The matrix test (test_rules_matrix.py) requires every loaded rule to appear in
a case list; this module's list is merged into that check.
"""

from datetime import datetime, timezone

import pytest

from app.detection import rule_loader
from app.detection.engine import evaluate_event
from app.schemas.event import NormalizedEvent

SYSMON = "Microsoft-Windows-Sysmon/Operational"

NEW_RULE_CASES = [
    (
        "Windows Logon Requested by a Non-Windows Process (Browser Credential Check)",
        "Security",
        4625,
        {"LogonProcessName": "Chrome", "LogonType": "2", "TargetUserName": "IEUser"},
        {"LogonProcessName": "User32", "LogonType": "2", "TargetUserName": "IEUser"},
    ),
    (
        "UAC Bypass via OskSupport.dll Written Outside the Windows Directory",
        SYSMON,
        11,
        {"Image": "C:\\Windows\\explorer.exe", "TargetFilename": "C:\\Users\\IEUser\\AppData\\Local\\Temp\\OskSupport.dll"},
        {"Image": "C:\\Windows\\System32\\svchost.exe", "TargetFilename": "C:\\Windows\\System32\\OskSupport.dll"},
    ),
    (
        "Accessibility Binary Launched from Outside the Windows Directory",
        SYSMON,
        1,
        {
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": 'C:\\windows\\system32\\cmd.exe "C:\\Program Files\\Windows Media Player\\osk.exe"',
        },
        {"Image": "C:\\Windows\\System32\\osk.exe", "CommandLine": '"C:\\Windows\\System32\\osk.exe"'},
    ),
    (
        "Process Spawned by the WMI Provider Host (Sysmon)",
        SYSMON,
        1,
        {"Image": "C:\\Windows\\System32\\notepad.exe", "ParentImage": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"},
        {"Image": "C:\\Windows\\System32\\WerFault.exe", "ParentImage": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"},
    ),
    (
        "Process Spawned by the WMI Provider Host (Security 4688)",
        "Security",
        4688,
        {"Image": "C:\\Windows\\System32\\notepad.exe", "ParentImage": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"},
        {"Image": "C:\\Windows\\System32\\notepad.exe", "ParentImage": "C:\\Windows\\explorer.exe"},
    ),
    (
        "User or Computer Account Modified by Another User Account",
        "Security",
        4738,
        {"SubjectUserName": "bob", "TargetUserName": "alice"},
        {"SubjectUserName": "SERVER002$", "TargetUserName": "lplui"},
    ),
    (
        "EFSRPC (PetitPotam) Call to a Remote Host",
        "Microsoft-Windows-RPC",
        5,
        {"InterfaceUuid": "{c681d488-d850-11d0-8c52-00c04fd90f7e}", "NetworkAddress": "\\\\10.0.2.14", "ProcNum": "0"},
        {"InterfaceUuid": "{367abb81-9844-35f1-ad32-98f038001003}", "NetworkAddress": "\\\\10.0.2.14", "ProcNum": "0"},
    ),
]


def _event(channel, event_id, data):
    return NormalizedEvent(
        host="WORKSTATION01",
        timestamp=datetime(2026, 10, 8, tzinfo=timezone.utc),
        event_id=event_id,
        channel=channel,
        raw={},
        event_data=data,
    )


@pytest.mark.parametrize("title,channel,event_id,matching,benign", NEW_RULE_CASES, ids=[c[0][:50] for c in NEW_RULE_CASES])
def test_new_rule_fires_on_the_real_shape_and_ignores_the_look_alike(title, channel, event_id, matching, benign):
    rules = rule_loader.load_rules()
    assert title in {m.title for m in evaluate_event(_event(channel, event_id, matching), rules)}
    assert title not in {m.title for m in evaluate_event(_event(channel, event_id, benign), rules)}


def test_efsrpc_rule_ignores_a_local_call():
    rules = rule_loader.load_rules()
    local = {"InterfaceUuid": "{c681d488-d850-11d0-8c52-00c04fd90f7e}", "NetworkAddress": "\\\\127.0.0.1"}
    titles = {m.title for m in evaluate_event(_event("Microsoft-Windows-RPC", 5, local), rules)}
    assert "EFSRPC (PetitPotam) Call to a Remote Host" not in titles


def test_account_change_rule_ignores_builtin_actors():
    rules = rule_loader.load_rules()
    for actor in ("SYSTEM", "LOCAL SERVICE", "-", "DC1$"):
        data = {"SubjectUserName": actor, "TargetUserName": "alice"}
        titles = {m.title for m in evaluate_event(_event("Security", 4738, data), rules)}
        assert "User or Computer Account Modified by Another User Account" not in titles, actor
