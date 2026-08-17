"""Day 5 verification (Pair 1): normalizer.py maps Sysmon fields to
NormalizedEvent for event IDs 1, 3, 11, and handles the raw evtx_reader.py
dict quirks (EventID as plain string vs. qualifier dict, EventData.Data as
a single dict vs. a list, empty Data elements).

The repo's only sample.evtx is not Sysmon data (confirmed while planning
Day 5 -- it's Windows System-log event ID 6013), so these use hand-crafted
fixtures shaped like real Sysmon xmltodict.parse() output instead.
"""

import pytest

from app.ingestion.normalizer import EventNormalizationError, _data_dict, normalize_event


def _system(event_id, computer="WORKSTATION01", system_time="2026-05-24T15:25:16.809914+00:00"):
    return {
        "Provider": {"@Name": "Microsoft-Windows-Sysmon"},
        "EventID": event_id,
        "TimeCreated": {"@SystemTime": system_time},
        "Computer": computer,
        "Security": {"@UserID": "S-1-5-18"},
    }


def _record(event_id, data_fields, computer="WORKSTATION01"):
    data = []
    for name, value in data_fields.items():
        item = {"@Name": name}
        if value is not None:
            item["#text"] = value
        data.append(item)
    return {
        "Event": {
            "System": _system(event_id, computer=computer),
            "EventData": {"Data": data},
        }
    }


def test_normalize_event_id_1_maps_process_command_line_user():
    record = _record(
        "1",
        {
            "Image": r"C:\Windows\System32\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "User": r"WORKSTATION01\alice",
        },
    )
    normalized = normalize_event(record)
    assert normalized.event_id == 1
    assert normalized.host == "WORKSTATION01"
    assert normalized.process == r"C:\Windows\System32\cmd.exe"
    assert normalized.command_line == "cmd.exe /c whoami"
    assert normalized.user == r"WORKSTATION01\alice"
    assert normalized.destination_ip is None


def test_normalize_event_id_3_maps_network_fields():
    record = _record(
        "3",
        {
            "Image": r"C:\Windows\System32\svchost.exe",
            "User": r"NT AUTHORITY\SYSTEM",
            "Protocol": "tcp",
            "SourceIp": "10.0.0.5",
            "SourcePort": "51345",
            "DestinationIp": "8.8.8.8",
            "DestinationPort": "443",
        },
    )
    normalized = normalize_event(record)
    assert normalized.event_id == 3
    assert normalized.process == r"C:\Windows\System32\svchost.exe"
    assert normalized.protocol == "tcp"
    assert normalized.source_ip == "10.0.0.5"
    assert normalized.source_port == 51345
    assert normalized.destination_ip == "8.8.8.8"
    assert normalized.destination_port == 443
    assert normalized.command_line is None


def test_normalize_event_id_11_maps_target_filename():
    record = _record(
        "11",
        {
            "Image": r"C:\Windows\System32\notepad.exe",
            "User": r"WORKSTATION01\alice",
            "TargetFilename": r"C:\Users\alice\Desktop\notes.txt",
        },
    )
    normalized = normalize_event(record)
    assert normalized.event_id == 11
    assert normalized.target_filename == r"C:\Users\alice\Desktop\notes.txt"
    assert normalized.process == r"C:\Windows\System32\notepad.exe"


def test_event_id_as_plain_string():
    record = _record("1", {"Image": "cmd.exe"})
    assert normalize_event(record).event_id == 1


def test_event_id_as_dict_with_qualifiers():
    record = _record({"@Qualifiers": "32768", "#text": "1"}, {"Image": "cmd.exe"})
    assert normalize_event(record).event_id == 1


def test_data_as_single_dict_not_list():
    data = _data_dict({"Data": {"@Name": "Image", "#text": "cmd.exe"}})
    assert data == {"Image": "cmd.exe"}


def test_data_as_list_of_dicts():
    data = _data_dict(
        {
            "Data": [
                {"@Name": "Image", "#text": "cmd.exe"},
                {"@Name": "User", "#text": "alice"},
            ]
        }
    )
    assert data == {"Image": "cmd.exe", "User": "alice"}


def test_data_element_with_no_text_key_maps_to_none():
    data = _data_dict({"Data": [{"@Name": "CommandLine"}]})
    assert data == {"CommandLine": None}


def test_unrecognized_event_id_leaves_type_specific_fields_none_but_populates_common_fields():
    record = _record("6013", {})
    normalized = normalize_event(record)
    assert normalized.event_id == 6013
    assert normalized.host == "WORKSTATION01"
    assert normalized.process is None
    assert normalized.command_line is None
    assert normalized.destination_ip is None


def test_missing_system_block_raises_event_normalization_error():
    with pytest.raises(EventNormalizationError):
        normalize_event({"Event": {}})


def test_missing_event_id_raises():
    record = _record("1", {"Image": "cmd.exe"})
    del record["Event"]["System"]["EventID"]
    with pytest.raises(EventNormalizationError):
        normalize_event(record)


def test_unparseable_timestamp_raises():
    record = _record("1", {"Image": "cmd.exe"})
    record["Event"]["System"]["TimeCreated"]["@SystemTime"] = "not-a-timestamp"
    with pytest.raises(EventNormalizationError):
        normalize_event(record)


def test_normalized_event_raw_field_holds_original_record():
    record = _record("1", {"Image": "cmd.exe"})
    normalized = normalize_event(record)
    assert normalized.raw == record


def test_raw_field_excluded_from_model_dump():
    record = _record("1", {"Image": "cmd.exe"})
    normalized = normalize_event(record)
    assert "raw" not in normalized.model_dump()
