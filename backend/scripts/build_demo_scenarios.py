"""One-shot authoring tool: builds app/demo/scenarios/demo_shift.{yml,jsonl}
from the real captures in backend/sample_logs/.

Run from backend/:

    ./venv/Scripts/python.exe scripts/build_demo_scenarios.py

This is a build-time tool, not something the app calls at runtime -- its
output (the manifest plus record files) is committed and is what
app/demo/scenario_loader.py actually reads. Re-run it only if the source
captures in sample_logs/ change or the segment definitions below change.

Every attack segment is selected by running the REAL pipeline
(normalize_event -> evaluate_event) over the source capture and keeping
exactly the records that trip a rule, grouped by which technique they hit --
the same posture as ai/tools/hallucination_spot_check.py. Nothing here
hand-writes a detection; expected_rule_titles and expected_technique_ids in
the manifest are read back off what the engine actually returned, so they
are a verified fact about the output, not a claim typed by hand. The noise
segment is asserted to trip zero rules before being written, so the
"1,500 real benign events, 0 matches" claim the demo makes is a checked
number, not an estimate.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # backend/

from app.detection.engine import evaluate_event  # noqa: E402
from app.detection.rule_loader import get_loaded_rules  # noqa: E402
from app.ingestion.evtx_reader import read_records_as_dicts  # noqa: E402
from app.ingestion.normalizer import EventNormalizationError, normalize_event  # noqa: E402

SAMPLE_LOGS_DIR = Path(__file__).resolve().parents[1] / "sample_logs"
OUT_DIR = Path(__file__).resolve().parents[1] / "app" / "demo" / "scenarios"

MALICIOUS_CAPTURE = SAMPLE_LOGS_DIR / "sysmon_malicious_demo.evtx"
NOISE_CAPTURE = SAMPLE_LOGS_DIR / "sysmon_vm_capture.evtx"

# Every technique in sysmon_malicious_demo.evtx, grouped into 3 segments by
# MITRE tactic story -- initial access/execution, persistence, then
# credential access plus lateral movement -- so the replay reads as an
# escalating chain rather than one flat pile of alerts. Placement (which
# segment) is a curatorial choice; membership within a segment (which
# records) is entirely engine-derived, not hand-picked.
SEGMENT_TECHNIQUES = {
    "seg_01_initial_access": {"T1059.001", "T1105", "T1218.005"},
    "seg_02_persistence": {"T1547.001", "T1546.012", "T1053.005"},
    "seg_03_credential_lateral": {"T1003.001", "T1003.002", "T1021.001", "T1021.002", "T1021.006", "T1071.001"},
}

NOISE_RECORD_COUNT = 1500
# Skip the capture opening (Sysmon config-change noise at startup) and take
# a contiguous run from the busiest region, so parent/child process
# co-occurrence in the sample stays coherent -- an examiner expanding one
# raw record should see a plausible neighbourhood, not a random scatter
# across a nine-hour capture.
NOISE_START_INDEX = 20000


def load_normalized(path: Path) -> list[tuple[dict, object]]:
    """Returns (raw_record, normalized_event) pairs, in capture order,
    skipping records that fail to normalize (matching the real ingest
    pipeline tolerance)."""
    pairs = []
    for record in read_records_as_dicts(path):
        try:
            normalized = normalize_event(record)
        except EventNormalizationError:
            continue
        pairs.append((record, normalized))
    return pairs


def build_attack_segments(rules):
    pairs = load_normalized(MALICIOUS_CAPTURE)

    segment_records: dict[str, list[dict]] = {name: [] for name in SEGMENT_TECHNIQUES}
    segment_rule_titles: dict[str, set[str]] = {name: set() for name in SEGMENT_TECHNIQUES}
    segment_technique_ids: dict[str, set[str]] = {name: set() for name in SEGMENT_TECHNIQUES}

    for record, normalized in pairs:
        matches = evaluate_event(normalized, rules)
        if not matches:
            continue
        for match in matches:
            for segment_name, techniques in SEGMENT_TECHNIQUES.items():
                if match.technique_id in techniques:
                    if record not in segment_records[segment_name]:
                        segment_records[segment_name].append(record)
                    segment_rule_titles[segment_name].add(match.title)
                    if match.technique_id:
                        segment_technique_ids[segment_name].add(match.technique_id)

    print(f"Attack capture: {len(pairs)} normalized records from {MALICIOUS_CAPTURE.name}")
    for name in SEGMENT_TECHNIQUES:
        print(
            f"  {name}: {len(segment_records[name])} records, "
            f"rules={sorted(segment_rule_titles[name])}, techniques={sorted(segment_technique_ids[name])}"
        )

    return segment_records, segment_rule_titles, segment_technique_ids


def build_noise_segment(rules) -> list[dict]:
    pairs = load_normalized(NOISE_CAPTURE)
    window = pairs[NOISE_START_INDEX : NOISE_START_INDEX + NOISE_RECORD_COUNT]

    matched = 0
    for _record, normalized in window:
        if evaluate_event(normalized, rules):
            matched += 1
    if matched:
        raise RuntimeError(
            f"noise window unexpectedly tripped {matched} rule match(es) -- "
            "the demo signal-to-noise claim depends on this being exactly 0"
        )

    print(f"Noise capture: {len(window)} records from {NOISE_CAPTURE.name}, verified 0 rule matches")
    return [record for record, _normalized in window]


def write_jsonl(records: list[dict], path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=True))
            f.write("\n")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rules = get_loaded_rules()

    segment_records, segment_rule_titles, segment_technique_ids = build_attack_segments(rules)
    noise_records = build_noise_segment(rules)

    write_jsonl(noise_records, OUT_DIR / "noise_vm_capture.jsonl")
    for name, records in segment_records.items():
        if not records:
            raise RuntimeError(f"segment {name} matched zero records -- check SEGMENT_TECHNIQUES")
        write_jsonl(records, OUT_DIR / f"{name}.jsonl")

    manifest = {
        "id": "demo_shift",
        "title": "Simulated 3-hour analyst shift",
        "description": (
            "Every record below is copied verbatim from a real Sysmon capture in "
            "backend/sample_logs/. The replay rewrites exactly one field -- "
            "Event.System.TimeCreated.@SystemTime -- to place the recorded activity "
            "onto the last window_minutes, preserving each segment own ordering "
            "and relative spacing. Nothing is synthesised; see "
            "backend/scripts/build_demo_scenarios.py for how each segment was selected."
        ),
        "host": "Nightowl",
        "window_minutes": 180,
        "duration_seconds": 180,
        "segments": [
            {
                "id": "noise",
                "kind": "noise",
                "title": "Ordinary workstation activity",
                "source_capture": NOISE_CAPTURE.name,
                "records_file": "noise_vm_capture.jsonl",
                "record_count": len(noise_records),
                "offset_minutes": -180,
                "time_scale": "fill",
                "expected_rule_titles": [],
                "expected_technique_ids": [],
            },
            {
                "id": "seg_01_initial_access",
                "kind": "attack",
                "title": "Encoded PowerShell, LOLBin download and tool staging",
                "source_capture": MALICIOUS_CAPTURE.name,
                "records_file": "seg_01_initial_access.jsonl",
                "record_count": len(segment_records["seg_01_initial_access"]),
                "offset_minutes": -170,
                "time_scale": 20,
                "expected_rule_titles": sorted(segment_rule_titles["seg_01_initial_access"]),
                "expected_technique_ids": sorted(segment_technique_ids["seg_01_initial_access"]),
            },
            {
                "id": "seg_02_persistence",
                "kind": "attack",
                "title": "Scheduled-task persistence",
                "source_capture": MALICIOUS_CAPTURE.name,
                "records_file": "seg_02_persistence.jsonl",
                "record_count": len(segment_records["seg_02_persistence"]),
                "offset_minutes": -95,
                "time_scale": 20,
                "expected_rule_titles": sorted(segment_rule_titles["seg_02_persistence"]),
                "expected_technique_ids": sorted(segment_technique_ids["seg_02_persistence"]),
            },
            {
                "id": "seg_03_credential_lateral",
                "kind": "attack",
                "title": "Credential dumping and lateral movement",
                "source_capture": MALICIOUS_CAPTURE.name,
                "records_file": "seg_03_credential_lateral.jsonl",
                "record_count": len(segment_records["seg_03_credential_lateral"]),
                "offset_minutes": -12,
                "time_scale": 20,
                "expected_rule_titles": sorted(segment_rule_titles["seg_03_credential_lateral"]),
                "expected_technique_ids": sorted(segment_technique_ids["seg_03_credential_lateral"]),
            },
        ],
    }

    import yaml

    manifest_path = OUT_DIR / "demo_shift.yml"
    with manifest_path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(manifest, f, sort_keys=False, allow_unicode=False, width=100)

    print(f"\nWrote {manifest_path}")


if __name__ == "__main__":
    main()
