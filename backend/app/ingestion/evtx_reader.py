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
from concurrent.futures import TimeoutError as FutureTimeout
from pathlib import Path
from typing import Iterator

import Evtx.Evtx as evtx
import xmltodict

from app.ingestion import evtx_rust

logger = logging.getLogger(__name__)

# path -> records rendered so far by the worker processes of an in-flight
# parallel read. Written by read_raw_records, read by the upload-job status
# endpoint for the live progress figure; the entry is removed when the read ends.
render_progress: dict[str, int] = {}

# Set in each worker process by _init_worker: a shared counter of rendered records.
_shared_counter = None

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
_MAX_WORKERS = 16


def _backend_wanted() -> str:
    """NIGHTOWL_EVTX_BACKEND: "python" (default -- python-evtx, the parser every
    rule and benchmark was validated against) or "rust" (opt-in experimental
    fast reader; see evtx_rust.py for why it is not the default)."""
    value = os.environ.get("NIGHTOWL_EVTX_BACKEND", "python").strip().lower()
    return "rust" if value == "rust" else "python"


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


def _init_worker(counter) -> None:
    global _shared_counter
    _shared_counter = counter


def _render_chunk_range(path: str, start: int, stop: int, as_dicts: bool = False) -> list:
    """Worker: the XML (or, with as_dicts, the parsed dict) of every record in
    chunks [start, stop), in file order. Parsing here rather than in the parent
    spreads the XML-to-dict cost across the same worker processes.
    Top-level so it can be pickled into a worker process."""
    out: list = []
    with evtx.Evtx(path) as log:
        for chunk in itertools.islice(log.chunks(), start, stop):
            before = len(out)
            if as_dicts:
                out.extend(_to_dict_or_empty(_render_record(record)) for record in chunk.records())
            else:
                out.extend(_render_record(record) for record in chunk.records())
            if _shared_counter is not None:
                with _shared_counter.get_lock():
                    _shared_counter.value += len(out) - before
    return out


def count_records(path: Path) -> int | None:
    """Total records in the file, from the per-chunk record-number ranges (a
    header-only scan, ~0.2 s for 50k records). Used for progress display only;
    None when the file's chunk headers cannot be read."""
    try:
        with evtx.Evtx(str(path)) as log:
            return sum(c.log_last_record_number() - c.log_first_record_number() + 1 for c in log.chunks())
    except Exception:  # noqa: BLE001 -- progress is cosmetic, never fail an upload for it
        return None


def read_raw_records(path: Path, workers: int | None = None) -> Iterator[str]:
    """Yields each record's raw XML string, in file order (see _read)."""
    return _read(path, workers, as_dicts=False)


def _read(path: Path, workers: int | None, as_dicts: bool) -> Iterator:
    """Yields each record, in file order, as raw XML or as a parsed dict.

    Large files are rendered chunk-range by chunk-range across worker
    processes (see _PARALLEL_MIN_CHUNKS); the output is identical to a
    sequential read, in the same order. Per-record failures are isolated as
    described in _render_record.
    """
    if _backend_wanted() == "rust" and evtx_rust.available():
        try:
            rendered = evtx_rust.read_raw_records(str(path))
        except Exception as e:  # noqa: BLE001 -- any Rust-parser rejection falls back
            logger.warning("rust evtx backend could not read %s (%s); using python-evtx", path, e)
        else:
            yield from (map(_to_dict_or_empty, rendered) if as_dicts else rendered)
            return
    try:
        with evtx.Evtx(str(path)) as log:
            header = log.get_file_header()
            if not header.check_magic():
                raise EvtxReadError(f"not a valid EVTX file (bad magic/signature): {path}")
            chunk_count = header.chunk_count()
            n_workers = workers if workers is not None else _worker_count()
            if n_workers <= 1 or chunk_count < _PARALLEL_MIN_CHUNKS:
                for record in log.records():
                    xml = _render_record(record)
                    yield _to_dict_or_empty(xml) if as_dicts else xml
                return
        # One contiguous range per worker: every task re-opens the file, and on
        # a machine with real-time antivirus each open of an attack-sample
        # capture is a scan -- many small tasks made 16 workers 40x SLOWER than
        # one process in measurement, while one range per worker is a clean
        # speed-up. Records are spread evenly across a file's chunks, so the
        # ranges balance well.
        step = max(1, -(-chunk_count // n_workers))
        ranges = [(start, min(start + step, chunk_count)) for start in range(0, chunk_count, step)]
        ctx = multiprocessing.get_context("spawn")
        counter = ctx.Value("i", 0)
        key = str(path)
        try:
            with ProcessPoolExecutor(
                max_workers=n_workers, mp_context=ctx, initializer=_init_worker, initargs=(counter,)
            ) as pool:
                futures = [pool.submit(_render_chunk_range, str(path), a, b, as_dicts) for a, b in ranges]
                for future in futures:  # in submission order == file order
                    while True:
                        try:
                            batch = future.result(timeout=0.3)
                            break
                        except FutureTimeout:
                            render_progress[key] = counter.value
                    render_progress[key] = counter.value
                    yield from batch
        finally:
            render_progress.pop(key, None)
    except FileNotFoundError:
        raise
    except EvtxReadError:
        raise
    except Exception as e:
        raise EvtxReadError(f"failed to read evtx file {path}: {e}") from e


def record_to_dict(xml_str: str) -> dict:
    """Converts one record's raw XML string into a plain dict."""
    return xmltodict.parse(xml_str)


def _to_dict_or_empty(xml_str: str) -> dict:
    try:
        return record_to_dict(xml_str)
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
        return {}


def read_records_as_dicts(path: Path) -> Iterator[dict]:
    return _read(path, None, as_dicts=True)


if __name__ == "__main__":
    count = 0
    for record_dict in read_records_as_dicts(SAMPLE_LOG_PATH):
        print(json.dumps(record_dict, indent=2))
        count += 1
        if count >= 3:
            break
    print(f"\nPrinted {count} of the sample file's records as JSON.")
