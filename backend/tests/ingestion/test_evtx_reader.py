"""Day 4 verification (Pair 1): EVTX reading + JSON conversion."""

import pytest

from app.ingestion.evtx_reader import (
    SAMPLE_LOG_PATH,
    EvtxReadError,
    read_raw_records,
    read_records_as_dicts,
    record_to_dict,
)


def test_read_raw_records_yields_xml_strings():
    records = list(read_raw_records(SAMPLE_LOG_PATH))
    assert len(records) > 0
    assert all(isinstance(r, str) and "<Event" in r for r in records)


def test_record_to_dict_parses_event_key():
    xml_str = next(read_raw_records(SAMPLE_LOG_PATH))
    record = record_to_dict(xml_str)
    assert "Event" in record


def test_read_records_as_dicts_matches_raw_count():
    raw_count = len(list(read_raw_records(SAMPLE_LOG_PATH)))
    dict_count = len(list(read_records_as_dicts(SAMPLE_LOG_PATH)))
    assert raw_count == dict_count


def test_missing_file_raises():
    with pytest.raises((FileNotFoundError, EvtxReadError)):
        list(read_raw_records(SAMPLE_LOG_PATH.parent / "does_not_exist.evtx"))


def test_a_record_that_fails_xml_parsing_is_skipped_not_fatal(monkeypatch):
    """Confirmed live against a real Windows-exported EVTX file: a record
    that reads fine as raw EVTX bytes but isn't well-formed XML once
    decoded (a stray control character in a field value is enough) used to
    raise xml.parsers.expat.ExpatError uncaught all the way through
    routes_ingest.py's `except EvtxReadError` (a different exception
    class), turning one bad record in an otherwise valid file into a
    whole-upload 500 -- see evtx_reader.py's read_records_as_dicts
    docstring. The whole file must still be readable, with the bad record
    degrading to a normalize_event-rejectable `{}` (same skip-and-count
    path as an EventNormalizationError) instead of aborting."""
    import app.ingestion.evtx_reader as evtx_reader_module

    real_record_to_dict = evtx_reader_module.record_to_dict
    call_count = {"n": 0}

    def flaky_record_to_dict(xml_str: str) -> dict:
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise ValueError("not well-formed (invalid token): line 40, column 87")
        return real_record_to_dict(xml_str)

    monkeypatch.setattr(evtx_reader_module, "record_to_dict", flaky_record_to_dict)

    raw_count = len(list(read_raw_records(SAMPLE_LOG_PATH)))
    results = list(read_records_as_dicts(SAMPLE_LOG_PATH))

    assert len(results) == raw_count  # nothing dropped from the stream -- degraded, not skipped-silently
    assert results[1] == {}  # the flaky record degraded to an empty dict
    assert all("Event" in r for i, r in enumerate(results) if i != 1)  # every other record parsed normally
