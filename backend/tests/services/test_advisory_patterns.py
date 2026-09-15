"""app/services/advisory_patterns.py -- narrow, verified-real event shapes
routed to the LLM second-opinion mechanism instead of a deterministic rule.
"""

from app.services.advisory_patterns import is_named_pipe_discovery, is_non_kernel_driver_service_installation


def test_lsass_pipe_connect_from_system_is_flagged():
    assert is_named_pipe_discovery(
        "Microsoft-Windows-Sysmon/Operational", 18, {"Image": "System", "PipeName": "\\lsass"}
    )


def test_srvsvc_pipe_connect_from_system_is_flagged():
    assert is_named_pipe_discovery(
        "Microsoft-Windows-Sysmon/Operational", 18, {"Image": "System", "PipeName": "\\srvsvc"}
    )


def test_unrelated_pipe_name_is_not_flagged():
    """Real content: this exact shape appears in the same verified sample
    as the \\lsass/\\srvsvc connects (System also opens \\browser, \\atsvc,
    \\wkssvc, ... in ordinary operation) -- must not blanket-match on
    event_id/channel/process alone."""
    assert not is_named_pipe_discovery(
        "Microsoft-Windows-Sysmon/Operational", 18, {"Image": "System", "PipeName": "\\wkssvc"}
    )


def test_non_system_process_is_not_flagged():
    """Real content: mmc.exe also opens named pipes in the same sample,
    to unrelated pipes -- the System-process narrowing is deliberate."""
    assert not is_named_pipe_discovery(
        "Microsoft-Windows-Sysmon/Operational", 18, {"Image": "C:\\Windows\\system32\\mmc.exe", "PipeName": "\\lsass"}
    )


def test_wrong_event_id_is_not_flagged():
    assert not is_named_pipe_discovery(
        "Microsoft-Windows-Sysmon/Operational", 17, {"Image": "System", "PipeName": "\\lsass"}
    )


def test_wrong_channel_is_not_flagged():
    """The Sysmon-channel guard: a Security-channel event with the same
    shape (hypothetically) must not match -- pipe_event's Sysmon 17/18 has
    no Security-channel counterpart today, but the channel check is not
    incidental."""
    assert not is_named_pipe_discovery("Security", 18, {"Image": "System", "PipeName": "\\lsass"})


# -- is_non_kernel_driver_service_installation -------------------------------
#
# Real content, both verified 2026-09-11 against the corresponding live
# fixtures: `ID4697-MSF payload deployed via service.evtx` (ServiceType
# 0x00000010, obfuscated-PowerShell Metasploit service stager) and
# `ID7045-4697-SMBexec service registration.evtx` (ServiceType 0x00000010,
# batch-file SMBExec persistence). The one loaded 4697 rule
# (kernel_driver_service_installed.yml) evaluates both but matches neither.


def test_ordinary_service_type_is_flagged():
    assert is_non_kernel_driver_service_installation("Security", 4697, {"ServiceType": "0x00000010"})


def test_kernel_driver_service_type_is_not_flagged():
    """The one ServiceType the existing rule already covers must stay
    exclusively that rule's job -- this pattern is the complement, not an
    overlapping second opinion on the same evidence."""
    assert not is_non_kernel_driver_service_installation("Security", 4697, {"ServiceType": "0x00000001"})


def test_missing_service_type_is_not_flagged():
    """No ServiceType field at all is no evidence either way -- stay
    conservative rather than guess."""
    assert not is_non_kernel_driver_service_installation("Security", 4697, {})


def test_wrong_event_id_is_not_flagged_for_service_installation():
    assert not is_non_kernel_driver_service_installation("Security", 4698, {"ServiceType": "0x00000010"})


def test_wrong_channel_is_not_flagged_for_service_installation():
    assert not is_non_kernel_driver_service_installation(
        "Microsoft-Windows-Sysmon/Operational", 4697, {"ServiceType": "0x00000010"}
    )
