"""The parallel EVTX reader must be a pure speed-up: same records, same order,
same content as the single-process read."""

from pathlib import Path

from app.ingestion import evtx_reader

FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "sample_logs" / "real_world_fixtures" / "detected" / "rogue_msi_url_1040_1042.evtx"
)


def test_parallel_read_is_identical_to_the_sequential_read():
    sequential = list(evtx_reader.read_raw_records(FIXTURE, workers=1))
    parallel = list(evtx_reader.read_raw_records(FIXTURE, workers=3))

    assert len(sequential) == 351
    assert parallel == sequential  # same records, same order, same text


def test_small_files_are_read_in_process(monkeypatch):
    """Below the chunk threshold no worker pool is started."""
    monkeypatch.setattr(evtx_reader, "_PARALLEL_MIN_CHUNKS", 10_000)

    def _boom(*args, **kwargs):
        raise AssertionError("a worker pool must not start for a small file")

    monkeypatch.setattr(evtx_reader, "ProcessPoolExecutor", _boom)
    assert len(list(evtx_reader.read_raw_records(FIXTURE, workers=4))) == 351


def test_an_invalid_file_still_raises_evtx_read_error(tmp_path):
    bad = tmp_path / "bad.evtx"
    bad.write_bytes(b"not an evtx file" * 100)
    try:
        list(evtx_reader.read_raw_records(bad, workers=4))
    except evtx_reader.EvtxReadError:
        return
    raise AssertionError("expected EvtxReadError")


def test_count_records_matches_the_records_actually_read():
    assert evtx_reader.count_records(FIXTURE) == 351


def test_count_records_is_none_for_an_unreadable_file(tmp_path):
    bad = tmp_path / "bad.evtx"
    bad.write_bytes(b"not an evtx file")
    assert evtx_reader.count_records(bad) is None


def test_render_progress_entry_is_removed_after_a_parallel_read():
    list(evtx_reader.read_raw_records(FIXTURE, workers=3))
    assert str(FIXTURE) not in evtx_reader.render_progress


def test_rust_backend_is_opt_in(monkeypatch):
    monkeypatch.delenv("NIGHTOWL_EVTX_BACKEND", raising=False)
    assert evtx_reader._backend_wanted() == "python"
    monkeypatch.setenv("NIGHTOWL_EVTX_BACKEND", "rust")
    assert evtx_reader._backend_wanted() == "rust"


def test_rust_guid_adapter_matches_python_evtx_guid_shape():
    from app.ingestion.evtx_rust import _to_python_evtx_style

    xml = '<Provider Guid="5770385F-C22A-43E0-BF4C-06F5698FFBD9"/><Data Name="ProcessGuid">5D9D6B6F-17B6-6A7F-C393-000000008600</Data>'
    out = _to_python_evtx_style(xml)
    assert 'Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"' in out
    assert ">{5d9d6b6f-17b6-6a7f-c393-000000008600}<" in out


def test_parallel_dicts_match_in_process_dicts(monkeypatch):
    monkeypatch.setenv("NIGHTOWL_EVTX_WORKERS", "1")
    sequential = list(evtx_reader.read_records_as_dicts(FIXTURE))
    monkeypatch.setenv("NIGHTOWL_EVTX_WORKERS", "3")
    parallel = list(evtx_reader.read_records_as_dicts(FIXTURE))
    assert len(sequential) == 351
    assert parallel == sequential
