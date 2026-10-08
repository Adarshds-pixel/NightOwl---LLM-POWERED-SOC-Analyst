"""detection/coverage.py: every event type is checked, routine or unchecked --
the split that lets a benign file read "Normal" instead of "Inconclusive"."""

from datetime import datetime, timedelta, timezone

from app.detection import rule_loader
from app.detection.coverage import CHECKED, ROUTINE, UNCHECKED, checked_pairs, classify
from app.detection.sequences import SEQUENCE_PATTERNS, SMB_FAN_OUT, detect_sequences
from app.ingestion.normalizer import canonical_channel, normalize_event
from tests.detection.test_sequences import _row

SYSMON = "Microsoft-Windows-Sysmon/Operational"


def _checked():
    return checked_pairs(rule_loader.load_rules())


def test_everyday_event_types_are_routine_not_unchecked():
    checked = _checked()
    assert classify("security", 5379, checked) == ROUTINE  # Credential Manager read
    assert classify("sysmon", 5, checked) == ROUTINE  # process exit
    assert classify("security", 4672, checked) == ROUTINE
    assert classify("system", 7036, checked) == ROUTINE  # service state change
    assert classify("application", 1001, checked) == ROUTINE
    assert classify("powershell", 4103, checked) == ROUTINE


def test_events_a_rule_or_detector_evaluates_are_checked():
    checked = _checked()
    assert classify("sysmon", 1, checked) == CHECKED  # process creation rules
    assert classify("security", 4625, checked) == CHECKED  # brute-force detector (sequence input)
    assert classify("security", 4771, checked) == CHECKED  # Kerberos spray detector
    assert classify("application", 18456, checked) == CHECKED
    assert classify("application", 1040, checked) == CHECKED  # explicit-EventID rule (MSI from URL)
    assert classify("system", 7045, checked) == CHECKED
    assert classify("rpc", 5, checked) == CHECKED  # EFSRPC rule


def test_security_relevant_or_unknown_event_types_stay_unchecked():
    checked = _checked()
    assert classify("security", 5136, checked) == UNCHECKED  # directory object modified
    assert classify("sysmon", 22, checked) == UNCHECKED  # DNS query: no rule, not noise
    assert classify(None, 6, checked) == UNCHECKED  # unrecognised channel


def test_system_log_cleared_is_a_notice_never_routine_noise():
    checked = _checked()
    assert classify("system", 104, checked) == CHECKED  # evaluated -> reported as a notice
    from app.detection.coverage import routine_reason

    assert routine_reason("system", 104) is None
    assert routine_reason("system", 7045) is None


def test_every_sequence_detector_input_counts_as_checked():
    checked = _checked()
    for pair in (("sysmon", 3), ("sysmon", 18), ("security", 4625), ("security", 5145), ("application", 18456)):
        assert pair in checked
    assert len(SEQUENCE_PATTERNS) == 9  # eight originals + SMB fan-out


def test_user_data_fields_are_read_so_a_log_clear_names_who_did_it():
    record = {
        "Event": {
            "System": {
                "EventID": "104",
                "Channel": "System",
                "Computer": "server002",
                "TimeCreated": {"@SystemTime": "2024-09-23T12:38:28.834879Z"},
            },
            "UserData": {
                "LogFileCleared": {
                    "@xmlns": "http://manifests.microsoft.com/win/2004/08/windows/eventlog",
                    "SubjectUserName": "lplui",
                    "SubjectDomainName": "SERVER002",
                    "Channel": "System",
                    "BackupPath": None,
                }
            },
        }
    }
    event = normalize_event(record)
    assert event.event_data["SubjectUserName"] == "lplui"
    assert event.event_data["Channel"] == "System"
    assert event.user == "SERVER002\lplui"
    assert "@xmlns" not in event.event_data


def test_etw_rpc_records_get_their_own_channel_instead_of_none():
    record = {
        "Event": {
            "System": {
                "EventID": "5",
                "Provider": {"@Name": "Microsoft-Windows-RPC"},
                "Computer": "host",
                "TimeCreated": {"@SystemTime": "2024-01-01T00:00:00Z"},
            },
            "EventData": {"Data": [{"@Name": "InterfaceUuid", "#text": "{x}"}]},
        }
    }
    event = normalize_event(record)
    assert event.channel == "Microsoft-Windows-RPC"
    assert canonical_channel(event.channel) == "rpc"
    # A channel-less record from any other provider stays unrecognised.
    record["Event"]["System"]["Provider"] = {"@Name": "Something-Else"}
    assert normalize_event(record).channel is None


# -- SMB fan-out detector ---------------------------------------------------


def _smb(host_ip: str, offset_seconds: int, image: str = "System"):
    return _row(
        3,
        {"Image": image, "DestinationIp": host_ip, "DestinationPort": "445", "Initiated": "true"},
        timestamp=datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=offset_seconds),
    )


def test_smb_fan_out_fires_when_one_process_hits_many_hosts_on_445_quickly():
    rows = [_smb(f"10.59.4.{n}", n) for n in range(21, 28)]  # 7 distinct hosts in 7 s
    matches = detect_sequences(rows)
    assert [m.rule_id for _anchor, m in matches if m.rule_id == SMB_FAN_OUT.rule_id] == [SMB_FAN_OUT.rule_id]


def test_smb_fan_out_ignores_a_client_talking_to_a_few_servers_or_a_slow_scan():
    few = [_smb(f"10.0.0.{n}", n) for n in range(1, 4)]
    assert not [m for _a, m in detect_sequences(few) if m.rule_id == SMB_FAN_OUT.rule_id]
    slow = [_smb(f"10.0.0.{n}", n * 120) for n in range(1, 8)]  # one host every 2 minutes
    assert not [m for _a, m in detect_sequences(slow) if m.rule_id == SMB_FAN_OUT.rule_id]
    repeated = [_smb("10.0.0.5", n) for n in range(10)]  # many connections, one host
    assert not [m for _a, m in detect_sequences(repeated) if m.rule_id == SMB_FAN_OUT.rule_id]
