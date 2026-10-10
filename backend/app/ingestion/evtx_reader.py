"""Reads raw Windows Event Log (.evtx) records and converts each one to a
plain, JSON-serializable Python dict.

This is deliberately the whole scope for Day 4: read a file, print raw
records, convert each to a dict. Sysmon-specific field mapping (event IDs
1, 3, 11 -> a common schema) and persistence to Postgres are Day 5's job
(see app/ingestion/normalizer.py, not yet written) -- keeping them out of
this module avoids coupling the raw reader to a schema that hasn't been
designed yet.
"""

import itertools
import json
import logging
import multiprocessing
import os
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Iterator

import Evtx.Evtx as evtx
import xmltodict

logger = logging.getLogger(__name__)

SAMPLE_LOG_PATH = Path(__file__).resolve().parents[2] / "sample_logs" / "sample.evtx"


class EvtxReadError(Exception):
    pass


# Reading is the slow part of an upload: python-evtx renders about 100 records
# per second on one core, which is 97% of the time a large capture takes. An EVTX
# file is a sequence of independent 64 KB chunks, so the chunks can be rendered
# by several processes at once with the SAME parser and byte-identical output.
# Files below this many chunks (about 1 MB) are read in-process: starting worker
# processes would cost more than it saves.
_PARALLEL_MIN_CHUNKS = 16
_MAX_WORKERS = 8


def _worker_count() -> int:
    configured = os.environ.get("NIGHTOWL_EVTX_WORKERS")
    if configured:
        try:
            return max(1, int(configured))
        except ValueError:
            pass
    return max(1, min(os.cpu_count() or 1, _MAX_WORKERS))


def _render_record(record) -> str:
    # One record can carry a corrupted UTF-16 sequence that raises deep inside
    # python-evtx; that must cost one record, not the whole file. "" flows on
    # and degrades through the same path as any unparseable XML.
    try:
        return record.xml()
    except Exception as e:  # noqa: BLE001
        logger.warning("skipping record that failed to render as XML: %s", e)
        return ""


def _render_chunk_range(path: str, start: int, stop: int) -> list[str]:
    """Worker: the XML of every record in chunks [start, stop), in file order.
    Top-level so it can be pickled into a worker process."""
    out: list[str] = []
    with evtx.Evtx(path) as log:
        for chunk in itertools.islice(log.chunks(), start, stop):
            out.extend(_render_record(record) for record in chunk.records())
    return out


def read_raw_records(path: Path, workers: int | None = None) -> Iterator[str]:
    """Yields each record's raw XML string, in file order.

    Large files are rendered chunk-range by chunk-range across worker
    processes (see _PARALLEL_MIN_CHUNKS); the output is identical to a
    sequential read, in the same order. Per-record failures are isolated as
    described in _render_record.
    """
    try:
        with evtx.Evtx(str(path)) as log:
            header = log.get_file_header()
            if not header.check_magic():
                raise EvtxReadError(f"not a valid EVTX file (bad magic/signature): {path}")
            chunk_count = header.chunk_count()
            n_workers = workers if workers is not None else _worker_count()
            if n_workers <= 1 or chunk_count < _PARALLEL_MIN_CHUNKS:
                for record in log.records():
                    yield _render_record(record)
                return
        # One contiguous range per worker: every task re-opens the file, and on
        # a machine with real-time antivirus each open of an attack-sample
        # capture is a scan -- many small tasks made 16 workers 40x SLOWER than
        # one process in measurement, while one range per worker is a clean
        # speed-up. Records are spread evenly across a file's chunks, so the
        # ranges balance well.
        step = max(1, -(-chunk_count // n_workers))
        ranges = [(start, min(start + step, chunk_count)) for start in range(0, chunk_count, step)]
        with ProcessPoolExecutor(max_workers=n_workers, mp_context=multiprocessing.get_context("spawn")) as pool:
            futures = [pool.submit(_render_chunk_range, str(path), a, b) for a, b in ranges]
            for future in futures:  # in submission order == file order
                yield from future.result()
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
