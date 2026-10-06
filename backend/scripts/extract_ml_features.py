"""CLI: build the benign feature matrix (scripts/ml_features.csv) from the
NightOwl-Benign-Dataset EVTX corpus.

The feature logic itself lives in app/ml/features.py -- it is imported by the
live ingest path and must not sit under scripts/ (excluded from the Docker
image). This module is now just the batch driver around it.
"""

import os
import sys
import glob
from pathlib import Path
import csv
import pickle
from collections import defaultdict

# Adjust sys.path to import from backend.app
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.ingestion.evtx_reader import read_records_as_dicts
from app.ingestion.normalizer import normalize_events
from app.ml.features import FEATURE_NAMES, extract_features  # noqa: F401  (re-exported for callers)


def get_evtx_files(dataset_dir: str) -> list[str]:
    return glob.glob(os.path.join(dataset_dir, "*.evtx"))


def main():
    dataset_dir = Path(__file__).resolve().parent.parent / "sample_logs" / "real_world_fixtures" / "NightOwl-Benign-Dataset"
    files = get_evtx_files(str(dataset_dir))
    
    print(f"Found {len(files)} EVTX files in dataset.")
    
    # Deduplication dict: (host, channel, event_record_id) -> NormalizedEvent
    dedup_dict = {}
    
    total_raw = 0
    
    cache_dir = Path(__file__).resolve().parent / "cache"
    cache_dir.mkdir(exist_ok=True)
    
    for f in files:
        print(f"Reading {Path(f).name}...")
        cache_file = cache_dir / (Path(f).name + ".pkl")
        if cache_file.exists():
            print(f"Loading {Path(f).name} from cache...")
            with open(cache_file, "rb") as cf:
                file_events = pickle.load(cf)
            for key, event in file_events.items():
                dedup_dict[key] = event
            total_raw += len(file_events)
            continue
            
        file_events = {}
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
                    file_events[key] = event
            except Exception as e:
                pass
        
        with open(cache_file, "wb") as cf:
            pickle.dump(file_events, cf)
                
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
