"""Upload sweep: what NightOwl would say about every sample log.

Runs the real detection engine, sequence detectors, coverage classification and
advisory patterns over every EVTX under backend/sample_logs and prints, per file,
the verdict an upload would show. Benign files must read "normal"; attack files
must read "suspicious" (or at least "review"). It reuses the benchmark's cached
normalised events, so a full sweep takes about a minute once the cache is warm.

    ./venv/Scripts/python scripts/upload_sweep.py            # table + pass/fail
    ./venv/Scripts/python scripts/upload_sweep.py --json out.json

Exit code 1 if any benign file is not "normal" or any attack file is "normal".
The browser walkthrough (see docs/DOCUMENTATION.md) covers the screens; this
covers every file.
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import run_detection_benchmark as bench  # noqa: E402
from app.detection.coverage import CHECKED, ROUTINE, checked_pairs, classify  # noqa: E402
from app.detection.rule_loader import load_rules  # noqa: E402
from app.ingestion.normalizer import canonical_channel  # noqa: E402
from app.services.advisory_patterns import (  # noqa: E402
    is_named_pipe_discovery,
    is_non_kernel_driver_service_installation,
)


def verdict(matches: int, unchecked: int, advisory: int, total: int) -> str:
    """Mirror of frontend/src/lib/verdict.ts::computeVerdict -- keep in sync."""
    if matches > 0:
        return "suspicious"
    if total == 0:
        return "empty"
    if unchecked > 0 or advisory > 0:
        return "review"
    return "normal"


def sweep_file(path: Path, rules, checked) -> dict:
    scanned = bench.scan(path, rules)
    events, _read, _skipped = bench.load_events(path)
    kinds: Counter[str] = Counter()
    unchecked_types: Counter[tuple[str | None, int]] = Counter()
    advisory = 0
    for event in events:
        token = canonical_channel(event.channel)
        kind = classify(token, event.event_id, checked)
        kinds[kind] += 1
        if kind not in (CHECKED, ROUTINE):
            unchecked_types[(event.channel, event.event_id)] += 1
        if is_named_pipe_discovery(event.channel, event.event_id, event.event_data) or (
            is_non_kernel_driver_service_installation(event.channel, event.event_id, event.event_data)
        ):
            advisory += 1
    matches = len(scanned["alerts"])
    return {
        "file": path.name,
        "events": len(events),
        "matches": matches,
        "techniques": sorted({a["technique"] for a in scanned["alerts"] if a["technique"]}),
        "checked": kinds[CHECKED],
        "routine": kinds[ROUTINE],
        "unchecked": len(events) - kinds[CHECKED] - kinds[ROUTINE],
        "advisory": advisory,
        "unchecked_types": [f"{c}:{e}x{n}" for (c, e), n in unchecked_types.most_common(6)],
        "verdict": verdict(matches, len(events) - kinds[CHECKED] - kinds[ROUTINE], advisory, len(events)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()

    bench._warm_cache()
    rules = load_rules()
    checked = checked_pairs(rules)
    sample = bench.SAMPLE_LOGS

    benign = [p for paths in bench.BENIGN_SOURCES.values() for p in paths]
    benign += [sample / "sample.evtx", sample / "sysmon_demo.evtx"]
    attacks = [p for d in bench.ATTACK_DIRS for p in sorted(d.glob("*.evtx"))]
    excluded = {n for n, t in bench.GROUND_TRUTH.items() if t["split"] == "excluded"}
    benign += [p for p in attacks if p.name in excluded]
    attacks = [p for p in attacks if p.name not in excluded]

    rows, failures = [], []
    for group, paths, want in (("benign", benign, {"normal"}), ("attack", attacks, {"suspicious", "review"})):
        for path in paths:
            if not path.exists():
                continue
            row = sweep_file(path, rules, checked)
            row["group"] = group
            row["ok"] = row["verdict"] in want
            rows.append(row)
            if not row["ok"]:
                failures.append(row)
            flag = "ok " if row["ok"] else "BAD"
            extra = ",".join(row["unchecked_types"][:3]) if row["unchecked"] else ""
            print(
                f"{flag} {group:6} {row['verdict']:10} ev={row['events']:6} m={row['matches']:3} "
                f"chk={row['checked']:6} rtn={row['routine']:6} unc={row['unchecked']:5} adv={row['advisory']:2} "
                f"{row['file'][:52]} {extra}"
            )

    print(f"\n{len(rows)} files: {sum(r['ok'] for r in rows)} as expected, {len(failures)} not")
    for group in ("benign", "attack"):
        g = [r for r in rows if r["group"] == group]
        print(f"  {group}: {Counter(r['verdict'] for r in g)}")
    if args.json:
        args.json.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
