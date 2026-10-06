"""Detection accuracy benchmark: runs the real engine over the fixture corpus
and reports recall on known-malicious samples and false positives on
known-clean ones.

Runs the pipeline in-process (`read_records_as_dicts` -> `normalize_event` ->
`evaluate_event`, plus `detect_sequences` for the 3-pattern sequence engine --
see detection/sequences.py), deliberately skipping HTTP and the database:
this measures *detection*, not ingestion plumbing, and it stays side-effect
free so it can be run against a live deployment without polluting its data.
`detect_sequences` needs an anchor "Event row" with an id/host/timestamp to
attach a match to; this script builds a throwaway one per normalized event
(never persisted -- ingest_service.py uses the real, DB-backed row) purely
so its own detection count reflects the same matches a real ingest would.

Two corpora, both already in the repo, kept in physically separate
directories (2026-09-05 -- previously mixed by filename convention alone,
which invited exactly the kind of "which of these is actually safe to
call clean" confusion this split now makes structurally impossible):

  malicious  sample_logs/real_world_fixtures/{detected,undetected}/
             real-world attack captures (public ATT&CK sample corpus).
             Split into two directories (2026-09-08) purely so the repo
             itself shows which fixtures the *current* rule set catches --
             this script still scans both together and scores every file
             as malicious regardless of which directory it's in, so a file
             with zero matches is still a false negative, never a correct
             verdict. detected/undetected is this script's own output
             recorded as a filesystem location, not an input filter.

  clean      sample_logs/demo_fixtures/noise_*.evtx    5 slices of ordinary
             workstation activity, verified clean at generation time by
             build_demo_evtx_fixtures.py -- Sysmon-only, so this alone never
             exercises a Security-channel rule's false-positive behavior.
             sample_logs/real_world_fixtures/benign/*.evtx -- real
             (not synthetic) captures from an ordinary PC:
             nightowl_benign_security.evtx (~32k Security-channel events)
             and nightowl_benign_powershell.evtx (~1.2k PowerShell-
             Operational events, 466 real 4104 script blocks + 10 real
             4103 module-logging records), added 2026-09-05 to close the
             Security- and PowerShell-channel false-positive-testing gaps
             respectively. Both contain their owner's real Windows
             username/hostname -- gitignored rather than committed (see
             root .gitignore), so a fresh clone simply has fewer clean
             fixtures rather than failing; nothing in this script requires
             them to be present.

Run from backend/:

    ./venv/Scripts/python.exe scripts/run_detection_benchmark.py
    ./venv/Scripts/python.exe scripts/run_detection_benchmark.py --json out.json

`--baseline <file>` diffs against an earlier JSON run and prints what newly
fires and what regressed, which is the point of keeping the JSON around.
"""

import argparse
import json
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # backend/

from app.detection.engine import evaluate_event  # noqa: E402
from app.detection.rule_loader import get_loaded_rules  # noqa: E402
from app.detection.sequences import detect_sequences  # noqa: E402
from app.ingestion.evtx_reader import EvtxReadError, read_records_as_dicts  # noqa: E402
from app.ingestion.normalizer import EventNormalizationError, normalize_event  # noqa: E402
from app.models.event import Event  # noqa: E402

SAMPLE_LOGS = Path(__file__).resolve().parents[1] / "sample_logs"
REAL_WORLD_DIR = SAMPLE_LOGS / "real_world_fixtures"
MALICIOUS_DIRS = (REAL_WORLD_DIR / "detected", REAL_WORLD_DIR / "undetected")
CLEAN_GLOB = sorted((SAMPLE_LOGS / "demo_fixtures").glob("noise_*.evtx")) + sorted(
    (REAL_WORLD_DIR / "benign").glob("*.evtx")
)


@dataclass
class FileResult:
    name: str
    records: int
    normalized: int
    skipped: int
    matches: int
    rule_titles: list[str] = field(default_factory=list)
    technique_ids: list[str] = field(default_factory=list)
    event_ids: list[int] = field(default_factory=list)
    elapsed_s: float = 0.0
    error: str | None = None

    @property
    def detected(self) -> bool:
        return self.matches > 0


def scan(path: Path, rules) -> FileResult:
    started = time.time()
    try:
        records = list(read_records_as_dicts(path))
    except EvtxReadError as e:
        return FileResult(name=path.name, records=0, normalized=0, skipped=0, matches=0, error=str(e))

    titles: Counter[str] = Counter()
    techniques: set[str] = set()
    event_ids: Counter[int] = Counter()
    normalized_count = 0
    skipped = 0
    matches = 0
    sequence_rows: list[tuple[Event, object]] = []

    for record in records:
        try:
            event = normalize_event(record)
        except EventNormalizationError:
            skipped += 1
            continue
        normalized_count += 1
        event_ids[event.event_id] += 1
        for match in evaluate_event(event, rules):
            matches += 1
            titles[match.title] += 1
            if match.technique_id:
                techniques.add(match.technique_id)
        # Throwaway anchor row (id only needs to be unique within this
        # scan; never persisted) -- see this module's docstring.
        sequence_rows.append((
            Event(
                id=normalized_count,
                host=event.host,
                timestamp=event.timestamp,
                event_id=event.event_id,
                channel=event.channel,
                process=None,
                command_line=None,
                user=None,
                event_record_id=None,
                raw_json={},
            ),
            event,
        ))

    for _anchor, match in detect_sequences(sequence_rows):
        matches += 1
        titles[match.title] += 1
        if match.technique_id:
            techniques.add(match.technique_id)

    return FileResult(
        name=path.name,
        records=len(records),
        normalized=normalized_count,
        skipped=skipped,
        matches=matches,
        rule_titles=sorted(titles),
        technique_ids=sorted(techniques),
        event_ids=sorted(event_ids),
        elapsed_s=round(time.time() - started, 1),
    )


def _print_section(title: str, results: list[FileResult], *, expect_detection: bool) -> None:
    print(f"\n{title}")
    print("-" * 100)
    for r in sorted(results, key=lambda x: (not x.detected, x.name)):
        if r.error:
            flag, detail = "ERR ", r.error[:60]
        elif r.detected:
            # A hit is what we want in the malicious corpus and a false
            # positive in the clean one -- same fact, opposite verdict.
            flag = "HIT " if expect_detection else "FP  "
            detail = ", ".join(r.rule_titles)[:70]
        else:
            flag = "MISS" if expect_detection else "ok  "
            detail = f"event ids present: {r.event_ids}"[:70] if expect_detection else ""
        print(f"  {flag} {r.name[:52]:52s} {r.matches:3d}  {detail}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", type=Path, help="write full results to this file")
    parser.add_argument("--baseline", type=Path, help="compare against an earlier --json run")
    args = parser.parse_args()

    rules = get_loaded_rules()
    print(f"Loaded {len(rules)} detection rules")

    malicious_files = sorted(p for d in MALICIOUS_DIRS for p in d.glob("*.evtx"))
    if not malicious_files:
        print(f"No fixtures found in {MALICIOUS_DIRS}", file=sys.stderr)
        return 1

    print(f"Scanning {len(malicious_files)} malicious + {len(CLEAN_GLOB)} clean fixtures "
          f"(large files take a while -- python-evtx parsing dominates)...")

    malicious = [scan(p, rules) for p in malicious_files]
    clean = [scan(p, rules) for p in CLEAN_GLOB]

    _print_section("MALICIOUS CORPUS (every file should be detected)", malicious, expect_detection=True)
    _print_section("CLEAN CORPUS (any hit is a false positive)", clean, expect_detection=False)

    detected = sum(1 for r in malicious if r.detected)
    false_positives = sum(1 for r in clean if r.detected)
    techniques = sorted({t for r in malicious for t in r.technique_ids})
    recall = detected / len(malicious) * 100 if malicious else 0.0

    print("\n" + "=" * 100)
    print(f"  Detection rate : {detected}/{len(malicious)}  ({recall:.1f}%)")
    print(f"  False positives: {false_positives}/{len(clean)}")
    print(f"  Techniques seen: {len(techniques)}  {', '.join(techniques) if techniques else '(none)'}")
    print("=" * 100)

    payload = {
        "detected": detected,
        "total_malicious": len(malicious),
        "recall_pct": round(recall, 1),
        "false_positives": false_positives,
        "total_clean": len(clean),
        "techniques": techniques,
        "rules_loaded": len(rules),
        "malicious": [asdict(r) for r in malicious],
        "clean": [asdict(r) for r in clean],
    }

    if args.baseline and args.baseline.exists():
        before = json.loads(args.baseline.read_text())
        was = {r["name"] for r in before["malicious"] if r["matches"] > 0}
        now = {r["name"] for r in malicious_names(payload)}
        print(f"\nvs baseline ({before['detected']}/{before['total_malicious']} -> {detected}/{len(malicious)}):")
        for name in sorted(now - was):
            print(f"  + newly detected  {name}")
        for name in sorted(was - now):
            print(f"  - REGRESSED       {name}")
        if not (now - was) and not (was - now):
            print("  (no change)")

    if args.json:
        args.json.write_text(json.dumps(payload, indent=2))
        print(f"\nWrote {args.json}")

    return 0


def malicious_names(payload: dict):
    return [r for r in payload["malicious"] if r["matches"] > 0]


if __name__ == "__main__":
    raise SystemExit(main())
