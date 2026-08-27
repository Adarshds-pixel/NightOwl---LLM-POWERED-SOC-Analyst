"""Manual debug helper: reads data/sample_logs/sysmon_demo.evtx through the
real ingestion/evtx_reader.py + ingestion/normalizer.py pipeline and prints
every normalized event's fields -- useful for eyeballing what a given .evtx
file actually parses to without spinning up the full POST /ingest route.

Run for real from backend/: `python scripts/print_evtx_records.py`
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # backend/

from app.ingestion.evtx_reader import read_records_as_dicts  # noqa: E402
from app.ingestion.normalizer import normalize_event  # noqa: E402

EVTX_PATH = Path(__file__).resolve().parents[1] / "sample_logs" / "sysmon_demo.evtx"

records = list(read_records_as_dicts(EVTX_PATH))

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
