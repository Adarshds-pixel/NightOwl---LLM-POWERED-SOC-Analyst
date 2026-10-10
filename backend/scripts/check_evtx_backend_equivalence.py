"""Compare the python-evtx and Rust (pyevtx-rs) EVTX readers record by record.

Run on Linux / Docker, where both parsers import side by side (on Windows their
package names collide):

    pip install evtx python-evtx
    python scripts/check_evtx_backend_equivalence.py sample_logs

For each .evtx under the given folder it normalizes every record through both
readers and prints the files whose normalized events differ. Exit code 1 if any
do -- the condition for the Rust backend to become the default.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import Evtx.Evtx as pyevtx  # noqa: E402
from evtx import PyEvtxParser  # noqa: E402

from app.ingestion.evtx_reader import _render_record, record_to_dict  # noqa: E402
from app.ingestion.evtx_rust import _to_python_evtx_style  # noqa: E402
from app.ingestion.normalizer import normalize_event  # noqa: E402


def _norm(xml: str):
    try:
        e = normalize_event(record_to_dict(xml))
    except Exception as ex:  # noqa: BLE001
        return ("ERR", type(ex).__name__)
    return (e.host, e.event_id, e.channel, e.event_record_id, sorted(e.event_data.items()))


def main(root: Path) -> int:
    different = 0
    for path in sorted(root.rglob("*.evtx")):
        with pyevtx.Evtx(str(path)) as log:
            py = [_render_record(r) for r in log.records()]
        try:
            rust = [_to_python_evtx_style(r["data"]) for r in PyEvtxParser(str(path)).records()]
        except Exception as e:  # noqa: BLE001
            print(f"RUST REJECTS {path}: {e}")
            different += 1
            continue
        bad = sum(1 for a, b in zip(py, rust) if _norm(a) != _norm(b)) + abs(len(py) - len(rust))
        if bad:
            different += 1
            print(f"DIFF {path}: {bad} of {len(py)} records")
    print(f"{different} file(s) differ")
    return 1 if different else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1] if len(sys.argv) > 1 else "sample_logs")))
