"""One-shot authoring tool: builds a set of real, independently-valid EVTX
test fixture files under sample_logs/demo_fixtures/ by re-exporting time-
filtered slices of the two existing real captures (sysmon_malicious_demo.evtx,
sysmon_vm_capture.evtx) via `wevtutil epl <file> <out> /lf:true /q:"<xpath>"`.

Why slicing, not fabricating: python-evtx (the only EVTX library this repo
depends on) is read-only, and there is no realistic way to hand-author valid
binary EVTX from scratch. `wevtutil epl` accepts an existing .evtx file as
its source (the /lf:true flag) as well as a live channel, so every output
file here is a genuine, independently-openable EVTX file containing nothing
but records copied verbatim from a real capture -- same honesty posture as
build_demo_scenarios.py, just producing raw .evtx instead of JSONL.

Malicious-file time windows were derived by re-running the real engine
(normalize_event -> evaluate_event) over every record in
sysmon_malicious_demo.evtx and reading back the exact timestamps of the 18
records that actually trip a rule (see the diagnostic in this file's git
history / PR description) -- the clusters below are natural, chronologically
contiguous groupings of those real matches, not a hand-picked selection.

Coverage: 12 of NightOwl's 15 rules fire somewhere in the two source
captures. The other 3 (Registry Run Key Persistence, Registry IFEO Debugger
Hijack, Certutil Download via urlcache/split) never fire anywhere in
sysmon_malicious_demo.evtx -- confirmed it has zero Sysmon EventID 13
(RegistryEvent) records at all, and its certutil.exe process-creation event
never got logged (likely intercepted by real-time AV before Sysmon could
record it -- see backend/scripts/generate_missing_rule_events.ps1, which
generates those 3 separately). If sample_logs/missing_rules_registry_certutil.evtx
exists (produced by that script), this tool re-exports it unmodified as one
more fixture and folds its techniques into the coverage summary.

As run on 2026-08-29: certutil fired correctly this time (13/15 total), but
the 2 registry rules still didn't -- this machine's Sysmon config, like the
original capture VM's, has no RegistryEvent rule enabled, so EventID 13 is
never logged here either regardless of what registry keys get written.
Closing that last gap needs an actual Sysmon config change (`sysmon -c`
with a config that adds a RegistryEvent include rule for the Run/RunOnce
and IFEO key paths), not more fixture generation -- out of scope here.

Run from backend/:

    ./venv/Scripts/python.exe scripts/build_demo_evtx_fixtures.py

Requires `wevtutil` (Windows only, ships with the OS -- no install needed).
"""

import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # backend/

from app.detection.engine import evaluate_event  # noqa: E402
from app.detection.rule_loader import get_loaded_rules  # noqa: E402
from app.ingestion.evtx_reader import read_records_as_dicts  # noqa: E402
from app.ingestion.normalizer import EventNormalizationError, normalize_event  # noqa: E402

SAMPLE_LOGS_DIR = Path(__file__).resolve().parents[1] / "sample_logs"
OUT_DIR = SAMPLE_LOGS_DIR / "demo_fixtures"

MALICIOUS_CAPTURE = SAMPLE_LOGS_DIR / "sysmon_malicious_demo.evtx"
NOISE_CAPTURE = SAMPLE_LOGS_DIR / "sysmon_vm_capture.evtx"
MISSING_RULES_CAPTURE = SAMPLE_LOGS_DIR / "missing_rules_registry_certutil.evtx"

TS_FMT = "%Y-%m-%dT%H:%M:%S.%f"


def to_xpath_ts(dt: datetime) -> str:
    return dt.strftime(TS_FMT)[:-3] + "Z"


def load_normalized(path: Path) -> list[tuple[int, dict, object]]:
    """Returns (index, raw_record, normalized_event) triples, in capture
    order, skipping records that fail to normalize."""
    triples = []
    for idx, record in enumerate(read_records_as_dicts(path)):
        try:
            normalized = normalize_event(record)
        except EventNormalizationError:
            continue
        triples.append((idx, record, normalized))
    return triples


# Natural, chronologically contiguous clusters of the 18 real rule matches
# found in sysmon_malicious_demo.evtx (2026-08-25, all within one 30s
# capture). Padding keeps each window comfortably clear of its neighbours --
# the nearest gap between any two clusters is 1.26s, all paddings below are
# well under that.
MALICIOUS_WINDOWS: dict[str, tuple[str, str]] = {
    "initial_execution_encoded_powershell": ("2026-08-25T11:37:17.000Z", "2026-08-25T11:37:17.950Z"),
    "execution_policy_bypass": ("2026-08-25T11:37:24.900Z", "2026-08-25T11:37:26.100Z"),
    "persistence_and_lolbin_beacon": ("2026-08-25T11:37:29.400Z", "2026-08-25T11:37:31.100Z"),
    "credential_access_mshta_lsass_sam": ("2026-08-25T11:37:38.200Z", "2026-08-25T11:37:40.400Z"),
    "lateral_movement_rdp_admin_winrm": ("2026-08-25T11:37:41.000Z", "2026-08-25T11:37:47.150Z"),
}

# (record-count, human label) for each noise slice. Windows are chosen by
# scanning for the first index >= a target fraction of the file that starts
# a run of this many consecutive clean (zero-match) records.
NOISE_SLICE_SPECS: list[tuple[float, int, str]] = [
    (0.05, 600, "noise_short_burst"),
    (0.25, 2000, "noise_mid_morning"),
    (0.50, 4000, "noise_afternoon_stretch"),
    (0.72, 1200, "noise_brief_window"),
    (0.90, 3000, "noise_late_session"),
]


def run_wevtutil(source: Path, target: Path, query: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["wevtutil", "epl", str(source), str(target), "/lf:true", f"/q:{query}", "/ow:true"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"wevtutil failed for {target.name}: {result.stderr or result.stdout}")


def build_malicious_slices(rules) -> dict[str, dict]:
    results = {}
    for name, (start, end) in MALICIOUS_WINDOWS.items():
        query = f"*[System[TimeCreated[@SystemTime>='{start}'] and TimeCreated[@SystemTime<='{end}']]]"
        target = OUT_DIR / f"{name}.evtx"
        run_wevtutil(MALICIOUS_CAPTURE, target, query)
        results[name] = verify_fixture(target, rules, expect_clean=False)
    return results


def build_full_kill_chain(rules) -> dict:
    target = OUT_DIR / "full_kill_chain.evtx"
    query = "*[System[TimeCreated[@SystemTime>='2026-08-25T11:37:16.000Z'] and TimeCreated[@SystemTime<='2026-08-25T11:37:47.500Z']]]"
    run_wevtutil(MALICIOUS_CAPTURE, target, query)
    return verify_fixture(target, rules, expect_clean=False)


def find_clean_window(triples: list[tuple[int, dict, object]], rules, start_frac: float, count: int) -> tuple[int, int]:
    """Scans forward from start_frac*len(triples) for the first run of
    `count` consecutive records with zero rule matches. Returns (start_idx,
    end_idx) as positions into `triples`."""
    n = len(triples)
    start = int(n * start_frac)
    pos = start
    while pos + count <= n:
        window = triples[pos : pos + count]
        if all(not evaluate_event(normalized, rules) for _idx, _record, normalized in window):
            return pos, pos + count
        pos += count  # skip past the dirty window rather than sliding one at a time
    raise RuntimeError(f"could not find a clean {count}-record window starting near fraction {start_frac}")


def build_noise_slices(rules) -> dict[str, dict]:
    print(f"Reading {NOISE_CAPTURE.name} (this is ~63MB, may take a minute)...")
    triples = load_normalized(NOISE_CAPTURE)
    print(f"  {len(triples)} normalized records")

    results = {}
    for start_frac, count, name in NOISE_SLICE_SPECS:
        start_idx, end_idx = find_clean_window(triples, rules, start_frac, count)
        start_ts = triples[start_idx][2].timestamp
        end_ts = triples[end_idx - 1][2].timestamp
        pad = timedelta(milliseconds=50)
        query = (
            f"*[System[TimeCreated[@SystemTime>='{to_xpath_ts(start_ts - pad)}'] "
            f"and TimeCreated[@SystemTime<='{to_xpath_ts(end_ts + pad)}']]]"
        )
        target = OUT_DIR / f"{name}.evtx"
        run_wevtutil(NOISE_CAPTURE, target, query)
        results[name] = verify_fixture(target, rules, expect_clean=True)
    return results


def build_missing_rules_fixture(rules) -> dict | None:
    if not MISSING_RULES_CAPTURE.exists():
        print(f"\n(skipping {MISSING_RULES_CAPTURE.name} -- not present yet)")
        return None
    target = OUT_DIR / "missing_rules_registry_certutil.evtx"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(MISSING_RULES_CAPTURE.read_bytes())
    return verify_fixture(target, rules, expect_clean=False)


def verify_fixture(path: Path, rules, *, expect_clean: bool) -> dict:
    """Re-parses the file this script just wrote and re-runs the real
    engine over it -- the only source of truth for what a fixture actually
    contains is asking the engine, never the filename."""
    matched_titles: set[str] = set()
    matched_techniques: set[str] = set()
    record_count = 0
    for record in read_records_as_dicts(path):
        record_count += 1
        try:
            normalized = normalize_event(record)
        except EventNormalizationError:
            continue
        for match in evaluate_event(normalized, rules):
            matched_titles.add(match.title)
            if match.technique_id:
                matched_techniques.add(match.technique_id)

    if expect_clean and matched_titles:
        raise RuntimeError(f"{path.name} was supposed to be clean noise but matched: {sorted(matched_titles)}")
    if not expect_clean and not matched_titles:
        raise RuntimeError(f"{path.name} was supposed to contain a detection but matched nothing")

    return {
        "size_bytes": path.stat().st_size,
        "record_count": record_count,
        "matched_titles": sorted(matched_titles),
        "matched_techniques": sorted(matched_techniques),
    }


def print_summary(all_results: dict[str, dict]) -> None:
    print("\n" + "=" * 100)
    print(f"{'file':45s} {'size':>10s} {'records':>9s}  techniques")
    print("-" * 100)
    covered_techniques: set[str] = set()
    covered_titles: set[str] = set()
    for name, info in all_results.items():
        size_kb = info["size_bytes"] / 1024
        print(f"{name + '.evtx':45s} {size_kb:9.1f}K {info['record_count']:9d}  {', '.join(info['matched_techniques']) or '(clean)'}")
        covered_techniques.update(info["matched_techniques"])
        covered_titles.update(info["matched_titles"])
    print("-" * 100)

    all_rule_titles = {r.title for r in get_loaded_rules()}
    print(f"\n{len(all_results)} fixture files written to {OUT_DIR}")
    print(f"Rule coverage across the new fixtures: {len(covered_titles)}/{len(all_rule_titles)}")
    missing = all_rule_titles - covered_titles
    if missing:
        print(f"Not yet covered: {sorted(missing)}")
        print("Run backend/scripts/generate_missing_rule_events.ps1 (elevated) and re-run this script to close the gap.")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rules = get_loaded_rules()

    all_results: dict[str, dict] = {}
    all_results["full_kill_chain"] = build_full_kill_chain(rules)
    all_results.update(build_malicious_slices(rules))
    all_results.update(build_noise_slices(rules))

    missing_rules_result = build_missing_rules_fixture(rules)
    if missing_rules_result:
        all_results["missing_rules_registry_certutil"] = missing_rules_result

    print_summary(all_results)


if __name__ == "__main__":
    main()
