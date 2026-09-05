"""app/services/advisory_patterns.py -- narrow, verified-real event shapes
routed to the LLM second-opinion mechanism instead of a deterministic rule.
"""

from app.services.advisory_patterns import is_named_pipe_discovery


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
