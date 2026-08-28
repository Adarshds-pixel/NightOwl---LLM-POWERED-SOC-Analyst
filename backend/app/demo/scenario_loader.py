"""Loads live-replay scenario manifests from `app/demo/scenarios/*.yml`.

Shaped deliberately like `detection/rule_loader.py`: a directory of
declarative files, real structural validation at load time, a module-level
cache with a `get_loaded_*`/`force_reload` accessor, and a malformed file
logged-and-skipped rather than crashing the whole set. A scenario is
"detection rules for the demo" in every way that matters architecturally.

Each segment's records live in a sibling `.jsonl` file -- one
`xmltodict`-shaped record per line, the exact dict `normalize_event`
already consumes (see `app/ingestion/normalizer.py`). They are pre-baked by
`backend/scripts/build_demo_scenarios.py` rather than parsed from the
source `.evtx` at load time, because the source captures are tens of
megabytes and parsing them on every backend startup (or every demo Start
click) would make an examiner wait through it live.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

SCENARIOS_DIR = Path(__file__).resolve().parent / "scenarios"


class ScenarioLoadError(Exception):
    pass


@dataclass(frozen=True)
class ScenarioSegment:
    id: str
    title: str
    kind: str
    """"attack" or "noise" -- purely descriptive, used by the UI to label a
    segment as it plays; both are ingested through the identical pipeline."""
    records_file: str
    offset_minutes: float
    time_scale: float | None
    """`None` spells the manifest's `time_scale: fill` -- see
    `app/demo/timeline.py`'s `build_schedule`."""
    source_capture: str
    record_count: int
    expected_rule_titles: list[str] = field(default_factory=list)
    expected_technique_ids: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DemoScenario:
    id: str
    title: str
    description: str
    host: str
    window_minutes: float
    duration_seconds: float
    segments: list[ScenarioSegment]


def _require(mapping: dict, key: str, path: Path) -> object:
    if key not in mapping:
        raise ScenarioLoadError(f"{path}: missing required field '{key}'")
    return mapping[key]


def _load_segment(raw: dict, path: Path) -> ScenarioSegment:
    time_scale_raw = raw.get("time_scale", 1.0)
    time_scale = None if time_scale_raw == "fill" else float(time_scale_raw)

    return ScenarioSegment(
        id=str(_require(raw, "id", path)),
        title=str(raw.get("title", raw.get("id", ""))),
        kind=str(raw.get("kind", "attack")),
        records_file=str(_require(raw, "records_file", path)),
        offset_minutes=float(_require(raw, "offset_minutes", path)),
        time_scale=time_scale,
        source_capture=str(raw.get("source_capture", "")),
        record_count=int(raw.get("record_count", 0)),
        expected_rule_titles=list(raw.get("expected_rule_titles") or []),
        expected_technique_ids=list(raw.get("expected_technique_ids") or []),
    )


def _load_one(path: Path) -> DemoScenario:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ScenarioLoadError(f"{path}: invalid YAML: {e}") from e

    if not isinstance(raw, dict):
        raise ScenarioLoadError(f"{path}: scenario file did not parse to a YAML mapping")

    segments_raw = _require(raw, "segments", path)
    if not isinstance(segments_raw, list) or not segments_raw:
        raise ScenarioLoadError(f"{path}: 'segments' must be a non-empty list")

    segments = [_load_segment(segment, path) for segment in segments_raw]

    return DemoScenario(
        id=str(_require(raw, "id", path)),
        title=str(raw.get("title", raw.get("id", ""))),
        description=str(raw.get("description", "")).strip(),
        host=str(_require(raw, "host", path)),
        window_minutes=float(_require(raw, "window_minutes", path)),
        duration_seconds=float(_require(raw, "duration_seconds", path)),
        segments=segments,
    )


def load_scenarios(scenarios_dir: Path = SCENARIOS_DIR) -> list[DemoScenario]:
    """Loads every `*.yml` in `scenarios_dir`. Missing directory or zero
    scenario files logs a warning and returns [] rather than raising -- same
    "an empty set shouldn't block the app from starting" policy as
    `rule_loader.load_rules`.
    """
    if not scenarios_dir.exists():
        logger.warning("demo scenarios directory does not exist: %s", scenarios_dir)
        return []

    scenarios: list[DemoScenario] = []
    for path in sorted(scenarios_dir.glob("*.yml")):
        try:
            scenarios.append(_load_one(path))
        except ScenarioLoadError as e:
            logger.warning("skipping malformed scenario file: %s", e)

    if not scenarios:
        logger.warning("no valid demo scenarios loaded from %s", scenarios_dir)
    return scenarios


def load_segment_records(segment: ScenarioSegment, scenarios_dir: Path = SCENARIOS_DIR) -> list[dict]:
    """Reads one segment's pre-baked JSONL records file, in file order (the
    order `build_demo_scenarios.py` wrote them in, which is capture order --
    callers rely on this being chronological within the segment)."""
    path = scenarios_dir / segment.records_file
    if not path.exists():
        raise ScenarioLoadError(f"segment '{segment.id}': records file not found: {path}")

    records = []
    with path.open(encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ScenarioLoadError(f"{path}:{line_number}: invalid JSON: {e}") from e
    return records


_scenario_cache: dict[str, DemoScenario] | None = None


def _load_cache(scenarios_dir: Path = SCENARIOS_DIR) -> dict[str, DemoScenario]:
    global _scenario_cache
    if _scenario_cache is None:
        _scenario_cache = {scenario.id: scenario for scenario in load_scenarios(scenarios_dir)}
    return _scenario_cache


def get_loaded_scenarios(force_reload: bool = False, scenarios_dir: Path = SCENARIOS_DIR) -> list[DemoScenario]:
    global _scenario_cache
    if force_reload:
        _scenario_cache = None
    return list(_load_cache(scenarios_dir).values())


def get_loaded_scenario(scenario_id: str, force_reload: bool = False, scenarios_dir: Path = SCENARIOS_DIR) -> DemoScenario:
    global _scenario_cache
    if force_reload:
        _scenario_cache = None
    cache = _load_cache(scenarios_dir)
    if scenario_id not in cache:
        raise ScenarioLoadError(f"unknown scenario id: {scenario_id!r}")
    return cache[scenario_id]
