"""EXPERIMENTAL, opt-in fast EVTX backend: the Rust `evtx` package (pyevtx-rs).

Enable with NIGHTOWL_EVTX_BACKEND=rust on Linux / Docker (on a case-insensitive
filesystem its `evtx` package collides with python-evtx's `Evtx` directory, so
on Windows it reports itself unavailable).

Measured over all 102 sample captures (257,241 records): it parses them in
about 4 s in total instead of minutes -- but it is NOT output-equivalent to
python-evtx, which is why it is not the default:
  * only 10 of 97 comparable files normalize identically;
  * hex numbers are not zero-padded (`0x3e7` vs `0x00000000000003e7`);
  * timestamps inside EventData are ISO ("...T07:36:48.809649Z") rather than
    python-evtx's "YYYY-MM-DD HH:MM:SS+00:00";
  * typed GUIDs are bare uppercase (handled below);
  * EventData blocks without field names render differently;
  * a few captures are rejected outright (the caller falls back to python-evtx);
  * record timestamps differ by at most 1 microsecond (rounding).
Rules, sequence detectors and the ML features were all built and benchmarked on
python-evtx output, so switching backends changes what they see. Before ever
making this the default, the differences above must be closed and
`scripts/check_evtx_backend_equivalence.py` (run on Linux, where both parsers
import) must report zero differing records.
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
