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
