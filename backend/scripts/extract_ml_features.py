import os
import sys
import glob
from pathlib import Path
from datetime import timedelta
import csv
from collections import defaultdict
import numpy as np

# Adjust sys.path to import from backend.app
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.ingestion.evtx_reader import read_records_as_dicts
from app.ingestion.normalizer import normalize_events
from app.schemas.event import NormalizedEvent

def get_evtx_files(dataset_dir: str) -> list[str]:
    return glob.glob(os.path.join(dataset_dir, "*.evtx"))

def extract_features(events: list[NormalizedEvent]) -> dict:
    # Process Features
    process_events = [e for e in events if e.event_id in (1, 4688)]
    process_names = [e.process.lower() for e in process_events if e.process]
    process_count = len(process_events)
    unique_process_count = len(set(process_names))
    rare_process_count = sum(1 for p in set(process_names) if process_names.count(p) == 1)
    
    # parent_child_relationship_count
    parent_child_relationship_count = sum(1 for e in process_events if e.parent_process and e.process)
    
    # parent_child_anomaly_count (placeholder: 0 for now)
    parent_child_anomaly_count = 0
    
    # PowerShell Features
    # Powershell event ID 4104 or PowerShell channel
    ps_events = [e for e in events if e.event_id == 4104 or (e.channel and "powershell" in e.channel.lower())]
    powershell_count = len(ps_events)
    
    encoded_command_count = sum(1 for e in events if e.command_line and ("-enc" in e.command_line.lower() or "-encodedcommand" in e.command_line.lower()))
    
    script_block_count = sum(1 for e in ps_events if e.event_id == 4104)
    
    # Network Features
    # Event ID 3
    network_events = [e for e in events if e.event_id == 3]
    network_event_count = len(network_events)
    unique_destinations = set(e.destination_ip for e in network_events if e.destination_ip)
    unique_destination_count = len(unique_destinations)
    
    # external_destination_count (naive: not starting with 10., 192.168., 172.16-31)
    def is_external(ip: str):
        if not ip: return False
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
            return False
        parts = ip.split(".")
        if len(parts) == 4 and parts[0] == "172" and 16 <= int(parts[1]) <= 31:
            return False
        return True
    
    external_destination_count = sum(1 for ip in unique_destinations if is_external(ip))
    unique_destination_port_count = len(set(e.destination_port for e in network_events if e.destination_port))
    
    # Command-Line Features
    cmd_lengths = [len(e.command_line) for e in process_events if e.command_line]
    average_command_length = float(np.mean(cmd_lengths)) if cmd_lengths else 0.0
    maximum_command_length = max(cmd_lengths) if cmd_lengths else 0
    
    argument_count = sum(len(e.command_line.split()) for e in process_events if e.command_line)
    suspicious_argument_count = sum(1 for e in process_events if e.command_line and ("hidden" in e.command_line.lower() or "bypass" in e.command_line.lower()))
    encoded_command_indicator = 1 if encoded_command_count > 0 else 0
    
    # User Features
    users = set(e.user.lower() for e in events if e.user)
    unique_user_count = len(users)
    processes_per_user = process_count / unique_user_count if unique_user_count > 0 else float(process_count)
    
    # Temporal Features (10-minute window)
    events_per_minute = len(events) / 10.0
    processes_per_minute = process_count / 10.0
    network_events_per_minute = network_event_count / 10.0
    
    return {
        "process_count": process_count,
        "unique_process_count": unique_process_count,
        "rare_process_count": rare_process_count,
        "parent_child_relationship_count": parent_child_relationship_count,
        "parent_child_anomaly_count": parent_child_anomaly_count,
        "powershell_count": powershell_count,
        "encoded_command_count": encoded_command_count,
        "script_block_count": script_block_count,
        "network_event_count": network_event_count,
        "unique_destination_count": unique_destination_count,
        "external_destination_count": external_destination_count,
        "unique_destination_port_count": unique_destination_port_count,
        "average_command_length": float(average_command_length),
        "maximum_command_length": maximum_command_length,
        "argument_count": argument_count,
        "suspicious_argument_count": suspicious_argument_count,
        "encoded_command_indicator": encoded_command_indicator,
        "unique_user_count": unique_user_count,
        "processes_per_user": float(processes_per_user),
        "events_per_minute": events_per_minute,
        "processes_per_minute": processes_per_minute,
        "network_events_per_minute": network_events_per_minute,
    }

def main():
    dataset_dir = Path(__file__).resolve().parent.parent / "sample_logs" / "real_world_fixtures" / "NightOwl-Benign-Dataset"
    files = get_evtx_files(str(dataset_dir))
    
    print(f"Found {len(files)} EVTX files in dataset.")
    
    # Deduplication dict: (host, channel, event_record_id) -> NormalizedEvent
    dedup_dict = {}
    
    total_raw = 0
    
    for f in files:
        print(f"Reading {Path(f).name}...")
        for raw_record in read_records_as_dicts(Path(f)):
            if not raw_record:
                continue
            total_raw += 1
            try:
                for event in normalize_events([raw_record]):
                    key = (event.host, event.channel, event.event_record_id)
                    # If event_record_id is None, we still include it but maybe can't dedup properly, 
                    # use a unique key fallback (like timestamp + event_id)
                    if event.event_record_id is None:
                        key = (event.host, event.channel, event.timestamp, event.event_id)
                    dedup_dict[key] = event
            except Exception as e:
                pass
                
    events = list(dedup_dict.values())
    print(f"Total raw events: {total_raw}")
    print(f"Total deduplicated events: {len(events)}")
    
    # Group by host and 10-minute window
    # 10-minute bucket: timestamp floored to nearest 10 mins
    
    windows = defaultdict(list)
    
    for event in events:
        # Floor minute to nearest 10
        minute_floored = (event.timestamp.minute // 10) * 10
        bucket_time = event.timestamp.replace(minute=minute_floored, second=0, microsecond=0)
        windows[(event.host, bucket_time)].append(event)
        
    print(f"Total 10-minute windows: {len(windows)}")
    
    features_list = []
    
    for (host, bucket_time), window_events in windows.items():
        if len(window_events) == 0:
            continue
        feats = extract_features(window_events)
        feats["host"] = host
        feats["window_start"] = bucket_time.isoformat()
        features_list.append(feats)
        
    output_path = Path(__file__).resolve().parent / "ml_features.csv"
    if features_list:
        keys = ["host", "window_start"] + list(features_list[0].keys())[:-2]
        # reorder keys slightly
        keys = list(dict.fromkeys(["host", "window_start"] + list(features_list[0].keys())))
        with open(output_path, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=keys)
            writer.writeheader()
            writer.writerows(features_list)
    print(f"Features exported to {output_path}")

if __name__ == "__main__":
    main()
