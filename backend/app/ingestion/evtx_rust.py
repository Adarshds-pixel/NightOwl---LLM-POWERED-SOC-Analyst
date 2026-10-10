"""EXPERIMENTAL, opt-in fast EVTX backend: the Rust `evtx` package (pyevtx-rs).

Enable with NIGHTOWL_EVTX_BACKEND=rust on Linux / Docker (on a case-insensitive
filesystem its `evtx` package collides with python-evtx's `Evtx` directory, so
on Windows it reports itself unavailable).

Measured over all 102 sample captures (348,188 records, 10 October 2026): it
reads them in 16 s in total instead of many minutes -- but a record-by-record
comparison found 0 records identical to python-evtx, which is why it is off:
  * 55% of record timestamps differ by 1-2 microseconds (python-evtx computes
    them in floating point; the Rust output lacks the digits to reproduce it);
  * hex numbers are not zero-padded (`0x3e7` vs `0x00000000000003e7`);
  * typed GUIDs are bare uppercase (the one difference handled below);
  * booleans are lowercase, empty attributes are omitted, binary data is hex
    rather than base64, string lists are separate elements;
  * typed timestamps inside EventData are ISO ("...T07:36:48.809649Z");
  * 19 records are not well-formed XML (stray control characters);
  * some files end with an unused chunk the parser raises on after the last
    record (all records are still returned before that).
Rules, sequence detectors and the ML features were all built and benchmarked on
python-evtx output, so the project decision is to keep python-evtx. This module
is kept only so the measurement can be repeated.
"""

import re

try:  # the Rust module exposes PyEvtxParser; python-evtx's `Evtx` does not
    from evtx import PyEvtxParser  # type: ignore[attr-defined]
except Exception:  # noqa: BLE001 -- not installed, or the name resolved to python-evtx
    PyEvtxParser = None

# The Rust renderer prints typed GUID values as bare UPPERCASE ("5D9D6B6F-..."),
# python-evtx as "{lowercase}" -- which is the form Sysmon rules and the
# normalizer's process-correlation were written against.
_BARE_GUID = re.compile(
    r"(?P<pre>[>\"])(?P<g>[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?P<post><|\")"
)


def _to_python_evtx_style(xml: str) -> str:
    return _BARE_GUID.sub(lambda m: f"{m['pre']}{{{m['g'].lower()}}}{m['post']}", xml)


def available() -> bool:
    return PyEvtxParser is not None


def read_raw_records(path: str) -> list[str]:
    """Every record's XML, adapted to python-evtx's shape. Raises on any file
    the Rust parser rejects so the caller can fall back (nothing is yielded
    partially: the whole file is rendered first)."""
    if PyEvtxParser is None:
        raise RuntimeError("Rust evtx backend not available")
    return [_to_python_evtx_style(r["data"]) for r in PyEvtxParser(path).records()]
