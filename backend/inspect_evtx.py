from pathlib import Path
from collections import Counter

from app.ingestion.evtx_reader import read_records_as_dicts

path = Path(r"..\data\sample_logs\sysmon_vm_capture.evtx")

counts = Counter()
total = 0

print("Scanning EVTX...")
print("This may take some time for the 66 MB file.")

for record in read_records_as_dicts(path):
    total += 1

    event = record.get("Event", {})
    system = event.get("System", {})
    event_id_data = system.get("EventID")

    if isinstance(event_id_data, dict):
        event_id = event_id_data.get("#text")
    else:
        event_id = event_id_data

    counts[event_id] += 1

print("\n==============================")
print("EVTX SUMMARY")
print("==============================")
print("TOTAL RECORDS:", total)

for event_id, count in sorted(counts.items(), key=lambda x: str(x[0])):
    print(f"Event ID {event_id}: {count}")