"""Reads raw Windows Event Log (.evtx) records and converts each one to a
plain, JSON-serializable Python dict.

This is deliberately the whole scope for Day 4: read a file, print raw
records, convert each to a dict. Sysmon-specific field mapping (event IDs
1, 3, 11 -> a common schema) and persistence to Postgres are Day 5's job
(see app/ingestion/normalizer.py, not yet written) -- keeping them out of
this module avoids coupling the raw reader to a schema that hasn't been
designed yet.
"""

import json
from pathlib import Path
from typing import Iterator

import Evtx.Evtx as evtx
import xmltodict

SAMPLE_LOG_PATH = Path(__file__).resolve().parents[3] / "data" / "sample_logs" / "sample.evtx"


class EvtxReadError(Exception):
    pass


def read_raw_records(path: Path) -> Iterator[str]:
    """Yields each record's raw XML string, in file order."""
    try:
        with evtx.Evtx(str(path)) as log:
            if not log.get_file_header().check_magic():
                raise EvtxReadError(f"not a valid EVTX file (bad magic/signature): {path}")
            for record in log.records():
                yield record.xml()
    except FileNotFoundError:
        raise
    except EvtxReadError:
        raise
    except Exception as e:
        raise EvtxReadError(f"failed to read evtx file {path}: {e}") from e


def record_to_dict(xml_str: str) -> dict:
    """Converts one record's raw XML string into a plain dict."""
    return xmltodict.parse(xml_str)


def read_records_as_dicts(path: Path) -> Iterator[dict]:
    for xml_str in read_raw_records(path):
        yield record_to_dict(xml_str)


if __name__ == "__main__":
    count = 0
    for record_dict in read_records_as_dicts(SAMPLE_LOG_PATH):
        print(json.dumps(record_dict, indent=2))
        count += 1
        if count >= 3:
            break
    print(f"\nPrinted {count} of the sample file's records as JSON.")
