"""detection/sequences.py -- the small, exactly-3-pattern sequence engine
(pending.md item 5). Field values below are the real ones verified against
the three corpus fixtures this engine is built from
(DE_ProcessHerpaderping_Sysmon_11_10_1_7.evtx,
discovery_enum_shares_target_sysmon_3_18.evtx,
kerberos_pwd_spray_4771.evtx), not invented shapes.
"""

from datetime import datetime, timedelta, timezone

from app.detection.sequences import (
    KERBEROS_PASSWORD_SPRAY,
    PROCESS_HERPADERPING,
    SMB_SHARE_ENUM_PROBE,
    detect_sequences,
)
from app.models.event import Event
from app.schemas.event import NormalizedEvent

BASE_TIME = datetime(2020, 10, 27, 10, 17, 18, tzinfo=timezone.utc)
_next_id = iter(range(1, 100_000))


def _row(
    event_id: int,
    event_data: dict[str, str | None],
    host: str = "LAPTOP-JU4M3I0E",
    timestamp: datetime = BASE_TIME,
    channel: str = "Microsoft-Windows-Sysmon/Operational",
) -> tuple[Event, NormalizedEvent]:
    row_id = next(_next_id)
    event = Event(
        id=row_id,
        host=host,
        timestamp=timestamp,
        event_id=event_id,
        channel=channel,
        process=None,
        command_line=None,
        user=None,
        event_record_id=None,
        raw_json={},
    )
    normalized = NormalizedEvent(
        host=host,
        timestamp=timestamp,
        event_id=event_id,
        channel=channel,
        event_data=event_data,
        raw={},
    )
    return event, normalized


# -- Process Herpaderping ---------------------------------------------------
# Real content: ProcessHerpaderping.exe (creator) writes samir.exe, then
# accesses its own spawned samir.exe process (PROCESS_ALL_ACCESS), which
# later loads its own (herpaderped) image.

CREATOR_GUID = "{00247c92-f3ae-5f97-0000-00106aba0418}"
ACCESSED_GUID = "{00247c92-f3ae-5f97-0000-00104ebd0418}"


def _herpaderping_rows(
    access_delay=timedelta(milliseconds=9),
    load_delay=timedelta(milliseconds=62),
    accessed_guid=ACCESSED_GUID,
    target_filename="C:\\Users\\bouss\\Downloads\\samir.exe",
    target_image="samir.exe",
    loaded_image="C:\\Users\\bouss\\Downloads\\samir.exe",
    source_process_guid=CREATOR_GUID,
):
    file_create = _row(
        11,
        {"ProcessGuid": CREATOR_GUID, "TargetFilename": target_filename},
        timestamp=BASE_TIME,
    )
    process_access = _row(
        10,
        {"SourceProcessGUID": source_process_guid, "TargetProcessGUID": accessed_guid, "TargetImage": target_image},
        timestamp=BASE_TIME + access_delay,
    )
    image_load = _row(
        7,
        {"ProcessGuid": accessed_guid, "ImageLoaded": loaded_image},
        timestamp=BASE_TIME + access_delay + load_delay,
    )
    return [file_create, process_access, image_load]


def test_process_herpaderping_fires_on_the_real_chain():
    matches = detect_sequences(_herpaderping_rows())

    assert len(matches) == 1
    anchor, match = matches[0]
    assert anchor.event_id == 7  # anchored on the concluding ImageLoad event
    assert match.rule_id == PROCESS_HERPADERPING.rule_id
    assert match.technique_id == "T1055"


def test_process_herpaderping_does_not_fire_when_process_access_is_unrelated():
    """Benign look-alike: a FileCreate, a ProcessAccess, and an ImageLoad
    all happen nearby, but the ProcessAccess's SourceProcessGUID doesn't
    match the FileCreate's creator -- coincidental proximity, not a real
    causal chain (e.g. unrelated AV scanner activity near an installer)."""
    rows = _herpaderping_rows(source_process_guid="{unrelated-guid}")

    assert detect_sequences(rows) == []


def test_process_herpaderping_does_not_fire_when_loaded_image_is_a_different_file():
    """Benign look-alike: the GUID chain lines up, but the file ultimately
    loaded is not the same file that was created -- e.g. a legitimate
    installer that creates one file and later, unrelatedly, loads a
    completely different DLL."""
    rows = _herpaderping_rows(loaded_image="C:\\Windows\\System32\\unrelated.dll")

    assert detect_sequences(rows) == []


def test_process_herpaderping_does_not_fire_outside_the_time_window():
    rows = _herpaderping_rows(load_delay=timedelta(seconds=20))

    assert detect_sequences(rows) == []


def test_process_herpaderping_requires_all_three_event_types():
    file_create, process_access, _image_load = _herpaderping_rows()
    assert detect_sequences([file_create, process_access]) == []


# -- SMB share enumeration probe ---------------------------------------------
# Real content: System (PID 4) connects a \srvsvc pipe; a remote client
# (over SMB, port 445, inbound) probes the same host around the same time.

SMB_PROCESS_GUID = "{dfae8213-f1b5-5cda-0000-0010eb030000}"


def _smb_enum_rows(
    network_delay=timedelta(seconds=1),
    pipe_name="\\srvsvc",
    initiated="False",
    source_port="445",
    host="DC1.insecurebank.local",
    network_host=None,
):
    pipe_connect = _row(
        18,
        {"ProcessGuid": SMB_PROCESS_GUID, "PipeName": pipe_name, "Image": "System"},
        host=host,
        timestamp=BASE_TIME,
    )
    network_connection = _row(
        3,
        {
            "ProcessGuid": SMB_PROCESS_GUID,
            "Image": "System",
            "Initiated": initiated,
            "SourcePort": source_port,
            "DestinationIp": "10.59.4.20",
        },
        host=network_host if network_host is not None else host,
        timestamp=BASE_TIME + network_delay,
    )
    return [pipe_connect, network_connection]


def test_smb_share_enum_probe_fires_on_the_real_pattern():
    matches = detect_sequences(_smb_enum_rows())

    assert len(matches) == 1
    anchor, match = matches[0]
    assert anchor.event_id == 18  # anchored on the pipe connect
    assert match.rule_id == SMB_SHARE_ENUM_PROBE.rule_id
    assert match.technique_id == "T1135"


def test_smb_share_enum_probe_does_not_fire_on_outbound_connections():
    """Benign look-alike: this host connecting OUT over port 445 (e.g. to
    a file share it's a client of) is not the same signal as a remote
    client probing IN."""
    rows = _smb_enum_rows(initiated="True")

    assert detect_sequences(rows) == []


def test_smb_share_enum_probe_does_not_fire_on_unverified_pipe_names():
    """\\wkssvc/\\browser are documented share/session-enumeration pipes
    too, but this pattern is scoped to only the one pipe name verified
    against a real sample -- see sequences.py's module-level comment."""
    rows = _smb_enum_rows(pipe_name="\\wkssvc")

    assert detect_sequences(rows) == []


def test_smb_share_enum_probe_does_not_fire_outside_the_time_window():
    rows = _smb_enum_rows(network_delay=timedelta(seconds=90))

    assert detect_sequences(rows) == []


def test_smb_share_enum_probe_does_not_fire_across_different_hosts():
    rows = _smb_enum_rows(network_host="SOME-OTHER-HOST")

    assert detect_sequences(rows) == []


# -- Kerberos password spray -------------------------------------------------
# Real content (kerberos_pwd_spray_4771.evtx): one source IP requests
# Kerberos tickets for 10 distinct target usernames within 23ms -- 7x 4768
# Status=0x6 (KDC_ERR_C_PRINCIPAL_UNKNOWN, invalid account), 2x 4771
# Status=0x18 (KDC_ERR_PREAUTH_FAILED, valid account/wrong password: one is
# literally named "backdoor"), then 2x 4768 Status=0x0 (success) for a
# "normal" account -- the eventual hit after the spray. The real capture's
# last event carries "::ffff:172.16.66.1" (IPv4-mapped IPv6) where every
# other one is the bare "172.16.66.1".

SPRAY_HOST = "01566s-win16-ir.threebeesco.com"
SPRAY_IP = "172.16.66.1"


def _kerberos_row(username, status, event_id=4768, ip=SPRAY_IP, timestamp=BASE_TIME, host=SPRAY_HOST):
    return _row(
        event_id,
        {"TargetUserName": username, "Status": status, "IpAddress": ip},
        host=host,
        timestamp=timestamp,
        channel="Security",
    )


def _kerberos_spray_rows(usernames=None, ip=SPRAY_IP, gap=timedelta(milliseconds=1), host=SPRAY_HOST):
    """`usernames` defaults to the real fixture's own 10, in the same
    order and status mix; each row lands `gap` after the previous one."""
    if usernames is None:
        usernames = [
            ("HD01", "0x00000006", 4768),
            ("admin", "0x00000006", 4768),
            ("svc-02", "0x00000006", 4768),
            ("HD02", "0x00000006", 4768),
            ("svc-01", "0x00000006", 4768),
            ("bob", "0x00000006", 4768),
            ("admin02", "0x00000006", 4768),
            ("Administrator", "0x00000018", 4771),
            ("backdoor", "0x00000018", 4771),
            ("normal", "0x00000000", 4768),
        ]
    return [
        _kerberos_row(username, status, event_id=event_id, ip=ip, timestamp=BASE_TIME + gap * i, host=host)
        for i, (username, status, event_id) in enumerate(usernames)
    ]


def test_kerberos_password_spray_fires_on_the_real_pattern():
    matches = detect_sequences(_kerberos_spray_rows())

    assert len(matches) == 1
    anchor, match = matches[0]
    assert match.rule_id == KERBEROS_PASSWORD_SPRAY.rule_id
    assert match.technique_id == "T1110.003"
    # Anchored on the 4th event -- the one that first pushes the distinct-
    # username count in the window up to the threshold.
    assert anchor.event_id == 4768
    assert anchor.timestamp == BASE_TIME + timedelta(milliseconds=3)


def test_kerberos_password_spray_fires_once_per_burst_not_once_per_event():
    """The burst has 10 distinct usernames, well past the threshold of 4 --
    this must not re-alert on every one of the remaining events once armed."""
    matches = detect_sequences(_kerberos_spray_rows())

    assert len(matches) == 1


def test_kerberos_password_spray_handles_ipv4_mapped_ipv6_source():
    """Real content: the fixture's own last event carries
    "::ffff:172.16.66.1" where every other one is the bare IPv4 form --
    both must group as the same source, or the burst silently splits into
    two under-threshold groups."""
    usernames = [
        ("HD01", "0x00000006", 4768),
        ("admin", "0x00000006", 4768),
        ("svc-02", "0x00000006", 4768),
    ]
    rows = _kerberos_spray_rows(usernames=usernames)
    # A 4th distinct FAILED account, arriving in the mapped-IPv6 form.
    mapped_row = _kerberos_row("normal", "0x00000006", ip="::ffff:172.16.66.1", timestamp=BASE_TIME + timedelta(milliseconds=3))

    assert detect_sequences(rows + [mapped_row]) != []


def test_kerberos_password_spray_does_not_fire_below_the_distinct_user_threshold():
    """Benign look-alike: a client requesting tickets for itself plus two
    service accounts in quick succession (e.g. a scheduled task chain) --
    3 distinct usernames, one below the threshold."""
    usernames = [
        ("alice", "0x00000000", 4768),
        ("svc-backup", "0x00000000", 4768),
        ("svc-report", "0x00000000", 4768),
    ]

    assert detect_sequences(_kerberos_spray_rows(usernames=usernames)) == []


def test_kerberos_password_spray_does_not_fire_on_repeated_failed_logons_for_one_account():
    """Benign look-alike (this is what a single-account brute force looks
    like, not a spray): many failures, but only ONE distinct username --
    the discriminating signal here is breadth across accounts, not raw
    failure count."""
    usernames = [("alice", "0x00000018", 4771) for _ in range(8)]

    assert detect_sequences(_kerberos_spray_rows(usernames=usernames)) == []


def test_kerberos_password_spray_does_not_fire_outside_the_time_window():
    usernames = [
        ("HD01", "0x00000006", 4768),
        ("admin", "0x00000006", 4768),
        ("svc-02", "0x00000006", 4768),
        ("HD02", "0x00000006", 4768),
    ]

    assert detect_sequences(_kerberos_spray_rows(usernames=usernames, gap=timedelta(seconds=30))) == []


def test_kerberos_password_spray_does_not_fire_across_different_source_ips():
    """Benign look-alike: a domain controller sees requests for 4 different
    accounts, but each from a different client IP -- ordinary multi-user
    traffic, not one source fanning out across accounts."""
    usernames = ["HD01", "admin", "svc-02", "HD02"]
    rows = [
        _kerberos_row(username, "0x00000006", ip=f"10.0.0.{i}", timestamp=BASE_TIME + timedelta(milliseconds=i))
        for i, username in enumerate(usernames)
    ]

    assert detect_sequences(rows) == []


def test_kerberos_password_spray_ignores_non_kerberos_events():
    assert detect_sequences([_kerberos_row("HD01", "0x00000006")]) == []


def test_detect_sequences_returns_all_three_patterns_independently():
    """The three patterns don't interfere with each other when more than
    one appears in the same ingest batch."""
    herpaderping_rows = _herpaderping_rows()
    smb_rows = _smb_enum_rows()
    kerberos_rows = _kerberos_spray_rows()

    matches = detect_sequences(herpaderping_rows + smb_rows + kerberos_rows)

    rule_ids = {match.rule_id for _anchor, match in matches}
    assert rule_ids == {
        PROCESS_HERPADERPING.rule_id,
        SMB_SHARE_ENUM_PROBE.rule_id,
        KERBEROS_PASSWORD_SPRAY.rule_id,
    }
