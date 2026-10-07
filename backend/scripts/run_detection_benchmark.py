"""Detection benchmark: the real rule engine + sequence detectors over every
attack and benign EVTX capture in the repo, measured three ways.

  1. Attack captures (sample_logs/real_world_fixtures/{detected,undetected}):
     * any-alert rate  -- the capture raised at least one alert (the only
       number the project used to report);
     * correct-technique rate -- at least one alert carries a technique that
       matches the capture's documented scenario (scripts/
       fixture_ground_truth.json; parent-technique match). An alert that only
       fires because the sample's author cleared the log before recording
       does not count as detecting the attack.
  2. Benign captures -- every alert is a false positive. Reported per rule and
     per file, as alert counts, not just "files with any hit":
       sample_logs/real_world_fixtures/NightOwl-Benign-Dataset/  (tracked)
       sample_logs/real_world_fixtures/benign/                   (optional, gitignored)
       sample_logs/demo_fixtures/noise_*.evtx                    (synthetic noise)
       plus any attack capture the ground truth marks as mislabeled-benign.
  3. Nothing else: no HTTP, no database, no ML layer (evaluated separately
     by scripts/eval_ml_model.py). Alerts are de-duplicated the same way
     ingest does (same rule, host, actor and target within 60 s = one alert).

All captures informed rule development, so these are development-set numbers;
see fixture_ground_truth.json's note.

Parsing EVTX is slow (the 56 MB Sysmon capture takes minutes), so normalized
events are cached under scripts/cache/ keyed by file size + mtime. Delete the
directory to force a re-parse.

    ./venv/Scripts/python.exe scripts/run_detection_benchmark.py
    ./venv/Scripts/python.exe scripts/run_detection_benchmark.py --json scripts/benchmark_results.json --markdown scripts/benchmark_results.md
"""

import argparse
import json
import pickle
import sys
import time
from collections import Counter, defaultdict
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.detection.engine import evaluate_event  # noqa: E402
from app.detection.rule_loader import load_rules  # noqa: E402
from app.detection.sequences import detect_sequences  # noqa: E402
from app.ingestion.evtx_reader import EvtxReadError, read_records_as_dicts  # noqa: E402
from app.ingestion.normalizer import EventNormalizationError, normalize_event  # noqa: E402
from app.services.ingest_service import ALERT_DEDUP_WINDOW, _alert_dedup_key  # noqa: E402

SAMPLE_LOGS = BACKEND / "sample_logs"
REAL_WORLD = SAMPLE_LOGS / "real_world_fixtures"
ATTACK_DIRS = (REAL_WORLD / "detected", REAL_WORLD / "undetected")
BENIGN_SOURCES = {
    "NightOwl-Benign-Dataset": sorted((REAL_WORLD / "NightOwl-Benign-Dataset").glob("*.evtx")),
    "benign (local only)": sorted((REAL_WORLD / "benign").glob("*.evtx")),
    "synthetic noise": sorted((SAMPLE_LOGS / "demo_fixtures").glob("noise_*.evtx")),
}
GROUND_TRUTH = json.loads((BACKEND / "scripts" / "fixture_ground_truth.json").read_text(encoding="utf-8"))["fixtures"]
CACHE_DIR = BACKEND / "scripts" / "cache" / "normalized"


def load_events(path: Path) -> tuple[list, int, int]:
    """(normalized events in timestamp order, records read, records skipped), cached."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache = _cache_path(path)
    use_cache = True
    if cache.exists():
        try:
            with open(cache, "rb") as f:
                return pickle.load(f)
        except (OSError, pickle.UnpicklingError, EOFError):
            # Antivirus can quarantine a cache file whose decoded strings look
            # like attack tooling (the psexec/meterpreter capture does) --
            # parse the capture directly instead and do not re-cache it.
            use_cache = False
    events, read, skipped = [], 0, 0
    try:
        for record in read_records_as_dicts(path):
            read += 1
            try:
                event = normalize_event(record)
            except EventNormalizationError:
                skipped += 1
                continue
            except Exception:  # noqa: BLE001 -- a corrupt record must not end the benchmark
                skipped += 1
                continue
            events.append(event.model_copy(update={"raw": {}}))
    except EvtxReadError:
        pass
    events.sort(key=lambda e: e.timestamp)
    result = (events, read, skipped)
    if not use_cache:
        return result
    # Write-then-rename so an interrupted run never leaves a truncated cache file.
    tmp = cache.with_suffix(".tmp")
    with open(tmp, "wb") as f:
        pickle.dump(result, f, protocol=pickle.HIGHEST_PROTOCOL)
    tmp.replace(cache)
    return result


def _cache_path(path: Path) -> Path:
    stat = path.stat()
    return CACHE_DIR / f"{path.name}.{stat.st_size}.{int(stat.st_mtime)}.pkl"


def _warm_cache() -> None:
    """Parse every uncached capture in its own short-lived subprocess, one at
    a time, so the memory python-evtx uses on a large file is returned to the
    OS before the next one starts (parsing everything in one process
    exhausted memory on a 16 GB machine)."""
    import subprocess

    paths = [p for d in ATTACK_DIRS for p in sorted(d.glob("*.evtx"))]
    paths += [p for group in BENIGN_SOURCES.values() for p in group]
    for path in paths:
        if _cache_path(path).exists():
            continue
        print(f"  parsing {path.name} ...", flush=True)
        subprocess.run([sys.executable, __file__, "--cache-one", str(path)], check=False)


def scan(path: Path, rules) -> dict:
    events, read, skipped = load_events(path)
    alerts: list[dict] = []
    open_alerts: dict[tuple, tuple[int, object]] = {}
    for event in events:
        for match in evaluate_event(event, rules):
            key = _alert_dedup_key(match.rule_id, event)
            previous = open_alerts.get(key)
            if previous is not None and event.timestamp - previous[1] <= ALERT_DEDUP_WINDOW:
                alerts[previous[0]]["occurrences"] += 1
                open_alerts[key] = (previous[0], event.timestamp)
                continue
            open_alerts[key] = (len(alerts), event.timestamp)
            alerts.append(
                {"rule": match.title, "technique": match.technique_id, "level": match.level, "occurrences": 1,
                 "sample": (event.command_line or event.process or json.dumps(event.event_data)[:160])}
            )
    rows = [(SimpleNamespace(id=i, host=e.host, timestamp=e.timestamp), e) for i, e in enumerate(events)]
    for _anchor, match in detect_sequences(rows):
        alerts.append({"rule": match.title, "technique": match.technique_id, "level": match.level, "occurrences": 1,
                       "sample": "(sequence)"})
    return {"name": path.name, "records": read, "events": len(events), "skipped": skipped, "alerts": alerts}


def _parent(technique: str | None) -> str | None:
    return technique.split(".")[0] if technique else None


def correct_technique(result: dict, expected: list[str]) -> bool:
    expected_parents = {_parent(t) for t in expected}
    return any(_parent(a["technique"]) in expected_parents for a in result["alerts"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--markdown", type=Path)
    parser.add_argument("--cache-one", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.cache_one:
        load_events(args.cache_one)
        return 0
    _warm_cache()

    started = time.time()
    rules = load_rules()
    print(f"{len(rules)} rules loaded")

    attack_files = [p for d in ATTACK_DIRS for p in sorted(d.glob("*.evtx"))]
    attack_rows, benign_rows = [], []
    for path in attack_files:
        truth = GROUND_TRUTH.get(path.name)
        if truth is None:
            print(f"WARNING: {path.name} has no ground-truth entry; skipped")
            continue
        result = scan(path, rules)
        if truth["split"] == "excluded":
            result["corpus"] = "mislabeled attack capture"
            benign_rows.append(result)
            continue
        result["expected"] = truth["expected"]
        result["any_alert"] = bool(result["alerts"])
        result["correct"] = correct_technique(result, truth["expected"])
        attack_rows.append(result)
        print(f"  attack  {'OK ' if result['correct'] else 'ANY' if result['any_alert'] else '-- '} {path.name}")
    for corpus, paths in BENIGN_SOURCES.items():
        for path in paths:
            result = scan(path, rules)
            result["corpus"] = corpus
            benign_rows.append(result)
            print(f"  benign  {len(result['alerts']):4d} alerts  {path.name}")

    n = len(attack_rows)
    any_hits = sum(r["any_alert"] for r in attack_rows)
    correct = sum(r["correct"] for r in attack_rows)
    fp_by_rule: Counter[str] = Counter()
    fp_events = 0
    benign_events = 0
    for r in benign_rows:
        benign_events += r["events"]
        for a in r["alerts"]:
            fp_by_rule[a["rule"]] += 1
            fp_events += a["occurrences"]
    fp_alerts = sum(fp_by_rule.values())

    summary = {
        "rules_loaded": len(rules),
        "attack_captures": n,
        "any_alert": any_hits,
        "correct_technique": correct,
        "benign_files": len(benign_rows),
        "benign_events": benign_events,
        "false_positive_alerts": fp_alerts,
        "false_positive_matched_events": fp_events,
        "benign_files_with_alerts": sum(1 for r in benign_rows if r["alerts"]),
        "false_positives_by_rule": dict(fp_by_rule.most_common()),
        "elapsed_s": round(time.time() - started, 1),
    }
    print()
    print(f"Attack captures: {n}")
    print(f"  any alert:          {any_hits}/{n} ({any_hits / n:.1%})")
    print(f"  correct technique:  {correct}/{n} ({correct / n:.1%})")
    print(f"Benign: {len(benign_rows)} files, {benign_events} events")
    print(f"  false-positive alerts: {fp_alerts} in {summary['benign_files_with_alerts']} file(s)")
    for rule, count in fp_by_rule.most_common():
        print(f"    {count:4d}  {rule}")

    if args.json:
        args.json.write_text(
            json.dumps({"summary": summary, "attack": attack_rows, "benign": benign_rows}, indent=2, default=str),
            encoding="utf-8",
        )
    if args.markdown:
        args.markdown.write_text(_markdown(summary, attack_rows, benign_rows), encoding="utf-8")
    return 0


def _markdown(summary: dict, attack_rows: list[dict], benign_rows: list[dict]) -> str:
    lines = [
        "# Detection benchmark results",
        "",
        "Generated by `backend/scripts/run_detection_benchmark.py` -- do not edit by hand. Rules + sequence detectors",
        "only (the ML anomaly layer is evaluated separately in ML.md). All attack captures informed rule development,",
        "so these are development-set numbers, not a held-out estimate.",
        "",
        f"* Rules loaded: {summary['rules_loaded']} (+ 3 sequence detectors)",
        f"* Attack captures: {summary['attack_captures']}",
        f"  * raised any alert: **{summary['any_alert']}/{summary['attack_captures']}**",
        f"  * raised an alert with the correct ATT&CK technique: **{summary['correct_technique']}/{summary['attack_captures']}**",
        f"* Benign captures: {summary['benign_files']} files, {summary['benign_events']:,} events",
        f"  * false-positive alerts: **{summary['false_positive_alerts']}** in {summary['benign_files_with_alerts']} file(s)",
        "",
        "## False positives by rule",
        "",
        "| alerts | rule |",
        "|---:|---|",
    ]
    lines += [f"| {c} | {rule} |" for rule, c in summary["false_positives_by_rule"].items()] or ["| 0 | -- |"]
    lines += ["", "## Attack captures", "", "| capture | expected | emitted techniques | verdict |", "|---|---|---|---|"]
    for r in sorted(attack_rows, key=lambda r: (not r["correct"], not r["any_alert"], r["name"].lower())):
        emitted = sorted({a["technique"] or "--" for a in r["alerts"]})
        verdict = "correct" if r["correct"] else "alert, wrong technique" if r["any_alert"] else "missed"
        lines.append(f"| {r['name']} | {', '.join(r['expected'])} | {', '.join(emitted) or '--'} | {verdict} |")
    lines += ["", "## Benign captures", "", "| corpus | file | events | alerts |", "|---|---|---:|---:|"]
    for r in benign_rows:
        lines.append(f"| {r['corpus']} | {r['name']} | {r['events']:,} | {len(r['alerts'])} |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
