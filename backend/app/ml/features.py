"""Behavioural feature extraction for the ML anomaly layer.

One 10-minute host window of NormalizedEvents in, one flat dict of numeric
features out. Lives under app/ (not scripts/) because the ingest path imports
it at request time -- backend/scripts is excluded from the Docker image by
both .dockerignore and the Dockerfile's COPY list, so importing it from
app.services.ingest_service silently disabled the whole ML phase in any
container build.

FEATURE_NAMES is the canonical column order. The trained model stores the
subset it was actually fitted on, so adding a feature here does not silently
corrupt an existing model -- app/ml/detector.py checks the names it was given.
"""

import numpy as np

from app.schemas.event import NormalizedEvent


def extract_features(events: list[NormalizedEvent]) -> dict:

    # 17 Heuristic Features (8 Basic + 9 Advanced)
    service_creation = 0
    account_group_change = 0
    log_cleared = 0
    lsass_access = 0
    lolbin_usage = 0
    suspicious_powershell = 0
    remote_named_pipe = 0
    admin_share_access = 0
    
    exploit_tool_regex_match = 0
    uac_bypass_registry_count = 0
    winrm_spawned_recon_count = 0
    suspicious_service_imagepath_count = 0
    accessibility_hijack_count = 0
    advanced_lolbin_count = 0
    db_failed_logon_count = 0
    domain_enumeration_count = 0
    account_tampering_count = 0
    
    lolbins_list = ['mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe', 'wmic.exe']
    sus_ps_list = ['-enc', '-w hidden', 'bypass', 'invoke-', 'iex', 'hidden', 'encodedcommand']

    for event in events:
        eid = event.event_id
        cmd = (getattr(event, 'command_line', "") or "").lower()
        ed = event.event_data or {}
        
        # 1. Basic Heuristics
        if eid in [7045, 4697]:
            service_creation += 1
        if eid in [4720, 4728, 4732, 4756, 4722, 4724, 4738, 4781, 4799]:
            account_group_change += 1
        if eid in [1102, 104]:
            log_cleared += 1
        
        if eid == 10:
            target = str(ed.get('TargetImage', '')).lower()
            if 'lsass.exe' in target:
                lsass_access += 1
        elif eid in [4656, 4663]:
            obj_name = str(ed.get('ObjectName', '')).lower()
            if 'lsass.exe' in obj_name:
                lsass_access += 1
                
        text = ""
        if eid in [1, 4688]:
            text = cmd
        elif eid == 4104:
            text = str(ed.get("ScriptBlockText", "")).lower()
            
        if text:
            for l in lolbins_list:
                if l in text:
                    lolbin_usage += 1
                    break
            if 'powershell' in text or eid == 4104:
                for sp in sus_ps_list:
                    if sp in text:
                        suspicious_powershell += 1
                        break
                        
        if eid == 18:
            pipe = str(ed.get('PipeName', '')).lower()
            if any(p in pipe for p in ['lsarpc', 'samr', 'svcctl', 'srvsvc']):
                remote_named_pipe += 1
        if eid == 5145:
            share = str(ed.get('ShareName', '')).lower()
            if 'ipc$' in share or 'admin$' in share or 'c$' in share:
                admin_share_access += 1
                
        # 2. Advanced Heuristics
        if 'uacme' in cmd or 'printspoofer' in cmd or 'winpwnage' in cmd:
            exploit_tool_regex_match += 1
            
        if eid in [12, 13, 14]:
            tgt = str(ed.get('TargetObject', '')).lower()
            if 'enablelua' in tgt or 'mscfile\\shell\\open\\command' in tgt:
                uac_bypass_registry_count += 1
        if eid == 1 and 'reg' in cmd and 'enablelua' in cmd:
            uac_bypass_registry_count += 1
            
        if eid == 1:
            parent = str(ed.get('ParentImage', '')).lower()
            if 'wsmprovhost.exe' in parent or 'winrshost.exe' in parent:
                if 'whoami' in cmd or 'ipconfig' in cmd or 'hostname' in cmd:
                    winrm_spawned_recon_count += 1
                    
        if eid in [4697, 7045]:
            img = str(ed.get('ImagePath', '')).lower()
            if 'cmd.exe' in img or '%comspec%' in img or '.tmp' in img:
                suspicious_service_imagepath_count += 1
                
        if eid == 1:
            img = str(ed.get('Image', '')).lower()
            if 'osk.exe' in img or 'sethc.exe' in img or 'utilman.exe' in img or 'consent.exe' in img:
                if 'cmd.exe' in str(ed.get('ParentImage', '')).lower():
                    accessibility_hijack_count += 1
                if 'osk.exe' in cmd and 'cmd.exe' in cmd:
                    accessibility_hijack_count += 1
        if eid in [12, 13]:
            if 'image file execution options\\osk.exe' in str(ed.get('TargetObject', '')).lower():
                accessibility_hijack_count += 1
                
        if eid == 1:
            if 'pcalua.exe' in cmd and '-a' in cmd:
                advanced_lolbin_count += 1
            if 'sdclt.exe' in cmd and '/kickoffelev' in cmd:
                advanced_lolbin_count += 1
        if eid == 7:
            if 'msiexec.exe' in str(ed.get('Image', '')).lower() and 'vbscript.dll' in str(ed.get('ImageLoaded', '')).lower():
                advanced_lolbin_count += 1
                
        if eid == 18456:
            db_failed_logon_count += 1
            
        if eid in [4798, 4799]:
            tgt = str(ed.get('TargetUserName', '')).lower()
            if tgt in ['administrators', 'users', 'remote desktop users', 'administrator']:
                domain_enumeration_count += 1
                
        if eid in [4738, 4742]:
            account_tampering_count += 1


    # Process Features
    process_events = [e for e in events if e.event_id in (1, 4688)]
    process_names = [e.process.lower() for e in process_events if e.process]
    process_count = len(process_events)
    unique_process_count = len(set(process_names))
    rare_process_count = sum(1 for p in set(process_names) if process_names.count(p) == 1)
    
    # LOLBins
    lolbins = {"certutil.exe", "bitsadmin.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "whoami.exe"}
    lolbin_execution_count = sum(1 for p in process_names if p in lolbins)
    
    parent_child_relationship_count = sum(1 for e in process_events if e.parent_process and e.process)
    
    # Parent-Child Anomaly (Standard child processes spawning non-standard children)
    suspicious_parents = {"winword.exe", "excel.exe", "powerpnt.exe", "acrord32.exe", "wscript.exe", "cscript.exe"}
    suspicious_children = {"cmd.exe", "powershell.exe", "certutil.exe", "wmic.exe"}
    parent_child_anomaly_count = 0
    for e in process_events:
        if e.parent_process and e.process:
            p_name = e.parent_process.lower()
            c_name = e.process.lower()
            if any(sp in p_name for sp in suspicious_parents) and any(sc in c_name for sc in suspicious_children):
                parent_child_anomaly_count += 1
    
    # PowerShell Features
    ps_events = [e for e in events if e.event_id == 4104 or (e.channel and "powershell" in e.channel.lower())]
    powershell_count = len(ps_events)
    
    encoded_command_count = sum(1 for e in events if e.command_line and ("-enc" in e.command_line.lower() or "-encodedcommand" in e.command_line.lower()))
    script_block_count = sum(1 for e in ps_events if e.event_id == 4104)
    
    # Network Features
    network_events = [e for e in events if e.event_id == 3]
    network_event_count = len(network_events)
    unique_destinations = set(e.destination_ip for e in network_events if e.destination_ip)
    unique_destination_count = len(unique_destinations)
    
    def is_external(ip: str):
        if not ip: return False
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127.") or ip.startswith("::1"):
            return False
        parts = ip.split(".")
        if len(parts) == 4 and parts[0] == "172" and 16 <= int(parts[1]) <= 31:
            return False
        return True
    
    external_destination_count = sum(1 for ip in unique_destinations if is_external(ip))
    unique_destination_port_count = len(set(e.destination_port for e in network_events if e.destination_port))
    
    # Suspicious Network Process
    suspicious_net_procs = {"powershell.exe", "cmd.exe", "certutil.exe", "wmic.exe", "mshta.exe"}
    suspicious_network_process_count = sum(1 for e in network_events if e.process and any(sp in e.process.lower() for sp in suspicious_net_procs))
    
    # Command-Line Features
    cmd_lengths = [len(e.command_line) for e in process_events if e.command_line]
    average_command_length = float(np.mean(cmd_lengths)) if cmd_lengths else 0.0
    maximum_command_length = max(cmd_lengths) if cmd_lengths else 0
    
    argument_count = sum(len(e.command_line.split()) for e in process_events if e.command_line)
    
    sus_keywords = ["hidden", "bypass", "downloadstring", "invoke-webrequest", "iwr", "iex", "invoke-expression", "mimikatz", "sekurlsa", "lsass", "dump"]
    suspicious_argument_count = sum(1 for e in process_events if e.command_line and any(k in e.command_line.lower() for k in sus_keywords))
    encoded_command_indicator = 1 if encoded_command_count > 0 else 0
    
    # Security Features (New)
    successful_logon_count = sum(1 for e in events if e.event_id == 4624)
    failed_logon_count = sum(1 for e in events if e.event_id == 4625)
    
    logon_types = [str(e.event_data.get("LogonType", "")) for e in events if e.event_id in (4624, 4625) and e.event_data.get("LogonType")]
    unique_logon_types_count = len(set(logon_types))
    
    remote_logon_count = sum(1 for e in events if e.event_id in (4624, 4625) and str(e.event_data.get("LogonType", "")) in ("3", "10"))
    admin_logon_count = sum(1 for e in events if e.event_id in (4624, 4625) and "admin" in str(e.event_data.get("TargetUserName", "")).lower())
    
    auth_users = set(str(e.event_data.get("TargetUserName", "")).lower() for e in events if e.event_id in (4624, 4625) and e.event_data.get("TargetUserName"))
    unique_logon_users = len(auth_users)
    
    auth_ips = set(str(e.event_data.get("IpAddress", "")) for e in events if e.event_id in (4624, 4625) and e.event_data.get("IpAddress") and e.event_data.get("IpAddress") != "-")
    unique_source_ips = len(auth_ips)
    
    special_privilege_logon_count = sum(1 for e in events if e.event_id == 4672)
    account_created_count = sum(1 for e in events if e.event_id == 4720)
    account_deleted_count = sum(1 for e in events if e.event_id == 4726)
    account_enabled_count = sum(1 for e in events if e.event_id == 4722)
    account_disabled_count = sum(1 for e in events if e.event_id == 4725)
    password_reset_count = sum(1 for e in events if e.event_id in (4723, 4724))
    
    group_member_added_count = sum(1 for e in events if e.event_id in (4728, 4732, 4756))
    group_member_removed_count = sum(1 for e in events if e.event_id in (4729, 4733, 4757))
    privileged_group_change_count = sum(1 for e in events if e.event_id in (4728, 4732, 4756, 4729, 4733, 4757) and "admin" in str(e.event_data.get("TargetUserName", "")).lower())
    
    directory_service_access_count = sum(1 for e in events if e.event_id == 4662)
    sensitive_object_access_count = sum(1 for e in events if e.event_id == 4663)
    lsass_access_count = sum(1 for e in events if e.event_id in (4656, 4663, 10) and "lsass" in str(e.event_data.get("ObjectName", str(e.event_data.get("TargetImage", "")))).lower())
    
    security_log_cleared_count = sum(1 for e in events if e.event_id == 1102)
    audit_policy_change_count = sum(1 for e in events if e.event_id == 4719)
    event_log_service_change_count = sum(1 for e in events if e.event_id in (1100, 104))
    
    # Ratios and Temporal
    total_events = len(events)
    unique_event_ids = len(set(e.event_id for e in events))
    
    total_logons = successful_logon_count + failed_logon_count
    authentication_failure_ratio = float(failed_logon_count / total_logons) if total_logons > 0 else 0.0
    
    security_events_count = sum(1 for e in events if e.event_id in (4624, 4625, 4672, 4720, 4722, 4725, 4726, 4723, 4724, 4728, 4732, 4756, 4729, 4733, 4757, 4662, 4663, 1102, 4719, 1100, 104, 4656))
    security_event_ratio = float(security_events_count / total_events) if total_events > 0 else 0.0
    
    powershell_to_process_ratio = float(powershell_count / process_count) if process_count > 0 else 0.0
    network_to_process_ratio = float(network_event_count / process_count) if process_count > 0 else 0.0
    process_to_logon_ratio = float(process_count / total_logons) if total_logons > 0 else 0.0
    
    # User Features
    users = set(e.user.lower() for e in events if e.user)
    unique_user_count = len(users)
    processes_per_user = process_count / unique_user_count if unique_user_count > 0 else float(process_count)
    
    events_per_minute = total_events / 10.0
    processes_per_minute = process_count / 10.0
    network_events_per_minute = network_event_count / 10.0
    
    return {
        "process_count": process_count,
        "lolbin_execution_count": lolbin_execution_count,
        "unique_process_count": unique_process_count,
        "rare_process_count": rare_process_count,
        "parent_child_relationship_count": parent_child_relationship_count,
        "parent_child_anomaly_count": parent_child_anomaly_count,
        "powershell_count": powershell_count,
        "encoded_command_count": encoded_command_count,
        "script_block_count": script_block_count,
        "network_event_count": network_event_count,
        "suspicious_network_process_count": suspicious_network_process_count,
        "unique_destination_count": unique_destination_count,
        "external_destination_count": external_destination_count,
        "unique_destination_port_count": unique_destination_port_count,
        "average_command_length": float(average_command_length),
        "maximum_command_length": maximum_command_length,
        "argument_count": argument_count,
        "suspicious_argument_count": suspicious_argument_count,
        "encoded_command_indicator": encoded_command_indicator,
        
        "successful_logon_count": successful_logon_count,
        "failed_logon_count": failed_logon_count,
        "unique_logon_types_count": unique_logon_types_count,
        "remote_logon_count": remote_logon_count,
        "admin_logon_count": admin_logon_count,
        "unique_logon_users": unique_logon_users,
        "unique_source_ips": unique_source_ips,
        "special_privilege_logon_count": special_privilege_logon_count,
        "account_created_count": account_created_count,
        "account_deleted_count": account_deleted_count,
        "account_enabled_count": account_enabled_count,
        "account_disabled_count": account_disabled_count,
        "password_reset_count": password_reset_count,
        "group_member_added_count": group_member_added_count,
        "group_member_removed_count": group_member_removed_count,
        "privileged_group_change_count": privileged_group_change_count,
        "directory_service_access_count": directory_service_access_count,
        "sensitive_object_access_count": sensitive_object_access_count,
        "lsass_access_count": lsass_access_count,
        "security_log_cleared_count": security_log_cleared_count,
        "audit_policy_change_count": audit_policy_change_count,
        "event_log_service_change_count": event_log_service_change_count,
        
        "total_events": total_events,
        "unique_event_ids": unique_event_ids,
        "authentication_failure_ratio": authentication_failure_ratio,
        "security_event_ratio": security_event_ratio,
        "process_to_logon_ratio": process_to_logon_ratio,
        
        "powershell_to_process_ratio": powershell_to_process_ratio,
        "network_to_process_ratio": network_to_process_ratio,
        "unique_user_count": unique_user_count,
        "processes_per_user": float(processes_per_user),
        "events_per_minute": events_per_minute,
        "processes_per_minute": processes_per_minute,
        "network_events_per_minute": network_events_per_minute,

        "service_creation": service_creation,
        "account_group_change": account_group_change,
        "log_cleared": log_cleared,
        "lsass_access": lsass_access,
        "lolbin_usage": lolbin_usage,
        "suspicious_powershell": suspicious_powershell,
        "remote_named_pipe": remote_named_pipe,
        "admin_share_access": admin_share_access,
        "exploit_tool_regex_match": exploit_tool_regex_match,
        "uac_bypass_registry_count": uac_bypass_registry_count,
        "winrm_spawned_recon_count": winrm_spawned_recon_count,
        "suspicious_service_imagepath_count": suspicious_service_imagepath_count,
        "accessibility_hijack_count": accessibility_hijack_count,
        "advanced_lolbin_count": advanced_lolbin_count,
        "db_failed_logon_count": db_failed_logon_count,
        "domain_enumeration_count": domain_enumeration_count,
        "account_tampering_count": account_tampering_count,
    }


# Canonical feature order, derived from the extractor itself so the two can
# never drift. Computed once at import on an empty window.
FEATURE_NAMES: list[str] = list(extract_features([]).keys())


def to_vector(features: dict, feature_names: list[str] | None = None) -> np.ndarray:
    """Project a feature dict onto an explicit column order.

    Always prefer this over list(features.values()) -- dict insertion order is
    an implementation detail of extract_features(), and a model trained on a
    different order (or on a subset, see detector.train) would score garbage
    without raising.
    """
    names = FEATURE_NAMES if feature_names is None else feature_names
    missing = [n for n in names if n not in features]
    if missing:
        raise KeyError(f"feature(s) missing from extraction: {missing}")
    return np.array([[float(features[n]) for n in names]])
