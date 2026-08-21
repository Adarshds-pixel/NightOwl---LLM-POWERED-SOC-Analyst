from pathlib import Path

from app.ingestion.evtx_reader import read_records_as_dicts
from app.ingestion.normalizer import normalize_event

p = Path(r"..\data\sample_logs\sysmon_demo.evtx")

records = list(read_records_as_dicts(p))

print("RECORDS:", len(records))

for i, record in enumerate(records, 1):
    print(f"\n--- EVENT {i} ---")

    event = normalize_event(record)

    print("event_id:", event.event_id)
    print("host:", event.host)
    print("process:", event.process)
    print("command_line:", event.command_line)
    print("user:", event.user)
    print("source_ip:", event.source_ip)
    print("source_port:", event.source_port)
    print("destination_ip:", event.destination_ip)
    print("destination_port:", event.destination_port)
    print("event_data:", event.event_data)