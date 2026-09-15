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
import logging
from pathlib import Path
from typing import Iterator

import Evtx.Evtx as evtx
import xmltodict

logger = logging.getLogger(__name__)

SAMPLE_LOG_PATH = Path(__file__).resolve().parents[2] / "sample_logs" / "sample.evtx"


class EvtxReadError(Exception):
    pass


def read_raw_records(path: Path) -> Iterator[str]:
    """Yields each record's raw XML string, in file order.

    `record.xml()` (python-evtx rendering one record's binary chunk data
    into an XML string) is wrapped per-record, not just by this function's
    outer try/except: confirmed live against a real Windows export, a
    single record can have a raw field value with an illegal UTF-16
    surrogate (a genuinely corrupted/truncated byte sequence -- not
    something ingest can fix, only skip), which raises UnicodeDecodeError
    deep inside python-evtx's own binary parser. Left to the outer
    try/except alone, this converts to EvtxReadError and aborts the whole
    generator -- rejecting an otherwise-good 1000+ record file over one
    bad record, the same "one bad record shouldn't fail the whole batch"
    gap record_to_dict's own per-record wrapping in read_records_as_dicts
    exists to close. `""` flows through to that function's `record_to_dict`
    call, fails to parse as XML, and degrades via the same existing path.
    """
    try:
        with evtx.Evtx(str(path)) as log:
            if not log.get_file_header().check_magic():
                raise EvtxReadError(f"not a valid EVTX file (bad magic/signature): {path}")
            for record in log.records():
                try:
                    yield record.xml()
                except Exception as e:
                    logger.warning("skipping record that failed to render as XML: %s", e)
                    yield ""
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
        try:
            yield record_to_dict(xml_str)
        except Exception as e:
            # A record that reads fine as raw EVTX bytes (read_raw_records
            # above succeeded) but isn't well-formed XML once decoded --
            # confirmed live against a real Windows export: a stray control
            # character embedded in a field value is enough to make
            # xmltodict.parse raise xml.parsers.expat.ExpatError. Left
            # uncaught, this propagated all the way past routes_ingest.py's
            # `except EvtxReadError` (a different exception class) into an
            # unhandled 500 on an otherwise perfectly valid upload --
            # exactly the "one bad record shouldn't fail the whole batch"
            # case routes_ingest.py's own docstring already promises for
            # EventNormalizationError, just not reachable from here. `{}`
            # fails normalize_event's own "record missing 'Event' block"
            # check, so this reuses that existing skip-and-count path
            # rather than adding a second one.
            logger.warning("skipping record that failed to parse as XML: %s", e)
            yield {}


if __name__ == "__main__":
    count = 0
    for record_dict in read_records_as_dicts(SAMPLE_LOG_PATH):
        print(json.dumps(record_dict, indent=2))
        count += 1
        if count >= 3:
            break
    print(f"\nPrinted {count} of the sample file's records as JSON.")
