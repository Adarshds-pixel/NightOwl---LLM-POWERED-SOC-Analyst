"""61-fixture failure/capability matrix -- Phase 0 of the evidence-driven
platform roadmap (see the approved plan, 2026-09-05).

Diagnostic only: this script does not change detection behavior in any
way, it only observes and classifies the *existing* pipeline's real
output. It answers, per fixture: did it parse, what telemetry does it
actually carry, how much of that telemetry has rule coverage, what fired,
and -- for every miss -- exactly which of the 12 failure categories
explains it, backed by real data rather than a guess.

Reuses the real pipeline throughout, no parallel implementation:
  - `read_records_as_dicts` / `normalize_event` / `evaluate_event` /
    `covered_event_ids` -- identical to run_detection_benchmark.py's
    in-process scan.
  - `ingest_records()` run against a **fresh in-memory SQLite session per
    fixture** (same engine/session setup `tests/conftest.py`'s
    `api_client` fixture uses) for real alert/incident counts and real
    MITRE technique resolution -- not inferred from match counts, actually
    persisted through the same code `POST /ingest` runs.

The per-miss classification for the 8 currently-known misses
(KNOWN_MISS_CLASSIFICATION below) is the evidence-based conclusion already
reached this session (see pending.md items 2 and 6) -- re-verify it against
this run's real output before trusting it; it is not re-derived from
scratch here, but it also isn't taken on faith: main() asserts the miss
set this run actually finds matches what these overrides expect, and
loudly flags anything that doesn't.

Run from backend/:
    ./venv/Scripts/python.exe scripts/build_failure_matrix.py
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # backend/

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.db.base import Base  # noqa: E402
from app.detection.engine import covered_event_ids, evaluate_event  # noqa: E402
from app.detection.rule_loader import LoadedRule, get_loaded_rules  # noqa: E402
from app.detection.sequences import SEQUENCE_PATTERNS  # noqa: E402
from app.ingestion.evtx_reader import EvtxReadError, read_records_as_dicts  # noqa: E402
from app.ingestion.normalizer import (  # noqa: E402
    EventNormalizationError,
    canonical_channel,
    normalize_event,
)
from app.models.incident import Incident  # noqa: E402
from app.services import ingest_service  # noqa: E402
from app.services.ingest_service import ingest_records  # noqa: E402

# This matrix measures the rules + sequence detectors only. The ML anomaly
# layer is evaluated separately (scripts/eval_ml_model.py, ML.md); letting it
# run here would count anomaly alerts as rule detections.
ingest_service.get_detector = lambda: None

_GROUND_TRUTH = json.loads(
    (Path(__file__).resolve().parent / "fixture_ground_truth.json").read_text(encoding="utf-8")
)["fixtures"]


def _correct_technique(name: str, techniques) -> bool:
    expected = {t.split(".")[0] for t in _GROUND_TRUTH.get(name, {}).get("expected", [])}
    return any(t and t.split(".")[0] in expected for t in techniques)

SAMPLE_LOGS = Path(__file__).resolve().parents[1] / "sample_logs"
# real_world_fixtures/ splits into detected/, undetected/ and benign/
# (2026-09-08, previously a single malicious/ + benign/ split) -- this
# script's whole premise is "every fixture in detected/undetected is
# malicious, classify its miss," so it reads both malicious subdirectories
# (never benign/) and reports on the full corpus regardless of a file's
# current detected/undetected status -- that status is this script's own
# output, not an input filter.
REAL_WORLD_DIR = SAMPLE_LOGS / "real_world_fixtures"
MALICIOUS_DIRS = (REAL_WORLD_DIR / "detected", REAL_WORLD_DIR / "undetected")

FAILURE_CATEGORIES: dict[int, str] = {
    1: "parser_gap",
    2: "channel_provider_gap",
    3: "event_id_coverage_gap",
    4: "normalization_gap",
    5: "field_mapping_gap",
    6: "rule_missing",
    7: "rule_too_narrow",
    8: "requires_sequence",
    9: "requires_cross_host_correlation",
    10: "insufficient_telemetry",
    11: "ambiguous_behavior",
    12: "benchmark_labeling_problem",
}

# Evidence-based classification for the current misses, reached this
# session via real field dumps against these exact files (see pending.md
# items 2 and 6 for the full writeup). This is a record of prior
# verification, not an assumption -- main() cross-checks it against this
# run's own miss set and flags any mismatch instead of silently trusting it.
KNOWN_MISS_CLASSIFICATION: dict[str, dict[str, object]] = {
    'CA_PetiPotam_etw_rpc_efsr_5_6.evtx': {
        "categories": [2],
        "reason": (
            "ETW/RPC channel (System.Channel is empty/None on these records, not Sysmon or Security) -- PetiPotam/EFSRPC coercion telemetry isn't in either currently-covered channel."
        ),
    },
    'Discovery_Remote_System_NamedPipes_Sysmon_18.evtx': {
        "categories": [6],
        "reason": (
            'Event ID 18 (pipe connect) IS covered (pipe_event category), but the only loaded pipe_event rule targets spoolss specifically. Confirmed real content: PipeName=\\lsass, Image=System -- a remote SMB named-pipe connection to \\lsass, not \\spoolss. No rule exists for this pattern; writing one needs care since System connecting to \\lsass/\\srvsvc over SMB is also fairly common legitimate traffic -- likely needs a remote-vs-local or frequency signal to stay low-noise, not a blanket PipeName match.'
        ),
    },
    'discovery_sysmon_18_Invoke_UserHunter_NetSessionEnum_DC-srvsvc.evtx': {
        "categories": [6],
        "reason": (
            "Same gap as Discovery_Remote_System_NamedPipes_Sysmon_18.evtx. Confirmed real content: PipeName=\\srvsvc, Image=System -- PowerView's Invoke-UserHunter NetSessionEnum technique connects to \\srvsvc, not \\spoolss."
        ),
    },
    'CA_4624_4625_LogonType2_LogonProc_chrome.evtx': {
        "categories": [10],
        "reason": (
            "Real content read directly: 3 successful LogonType 2 (interactive) logons via chrome.exe as the logon process, plus exactly 1 failed logon (4625) -- 4 events total. 4624/4625 are fully covered event IDs (no channel/parser gap), but this file's own signal is too thin to justify a rule: 1 failure is not a brute-force pattern (the project's own Kerberos-spray rule requires 4 distinct targets in a window, well below the real spray sample's 10, specifically to avoid firing on normal single mistypes), and nothing about the 3 successful logons is anomalous on its own. Writing a rule here would mean inventing a threshold with no real population of logon-failure samples to calibrate or benign-test it against -- exactly the overfitting this project's own discipline avoids. Not pursued this pass; revisit if a real, higher-volume failed-logon sample is ever added."
        ),
    },
    'Sysmon_UACME_32.evtx': {
        "categories": [6],
        "reason": (
            "UACME method 32 (UIPI bypass via an osk.exe DLL hijack). The only observable steps are explorer.exe writing OskSupport.dll to Temp, consent.exe prompts and cmd.exe launching a copy of osk.exe from 'C:\\Program Files\\Windows Media Player\\'. No generalisable single-event or sequence signature without overfitting to this sample; previously 'detected' only by the over-broad Temp-write rule, with the wrong technique."
        ),
    },
    'discovery_sysmon_3_Invoke_UserHunter_SourceMachine.evtx': {
        "categories": [11],
        "reason": (
            "9 Sysmon network events: PowerShell querying LDAP (389) on a DC and System making SMB (445) connections to two hosts. That volume is indistinguishable from a normal domain member; previously 'detected' only by the PowerShell-network rule (removed: it fired on all PowerShell traffic), with the wrong technique."
        ),
    },
}


@dataclass
class FixtureRecord:
    name: str
    behavior_hint: str
    parsed_ok: bool
    parse_error: str | None
    records_read: int
    channels: list[str]
    providers: list[str]
    event_id_counts: dict[str, int]
    normalized_count: int
    skipped_count: int
    covered_count: int
    uncovered_count: int
    uncovered_breakdown: list[dict[str, object]]
    matched_rule_ids: list[str]
    matched_rule_titles: list[str]
    matched_technique_ids: list[str]
    alerts_created: int
    incident_ids: list[int]
    mitre_technique_ids: list[str]
    detected: bool
    # An alert carrying a technique from the capture's documented scenario
    # (fixture_ground_truth.json) -- an alert from an unrelated rule, e.g. the
    # sample author clearing the log, does not count.
    correct_technique: bool = False
    classification_codes: list[int] = field(default_factory=list)
    classification_labels: list[str] = field(default_factory=list)
    reason: str = ""
    manual_review_needed: bool = False


def _behavior_hint(filename: str) -> str:
    """Purely descriptive, derived from the public corpus's own filename
    convention (e.g. `CA_`/`DE_`/`LM_`/`discovery_`/`exec_`/`privesc_`/
    `persistence_` prefixes) -- a report label only. Never consulted by
    any detection/classification logic in this script or the app itself.
    """
    stem = filename[:-5] if filename.lower().endswith(".evtx") else filename
    return stem.replace("_", " ").strip()


def _make_session_factory():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autocommit=False, autoflush=False)


_DISTANT_FUTURE = datetime.max.replace(tzinfo=timezone.utc)


def _timestamp_sort_key(record: dict) -> datetime:
    """Mirrors routes_ingest.py's pre-ingest sort exactly -- ingest_records
    (matched_at=None) requires ascending event timestamps."""
    try:
        return normalize_event(record).timestamp
    except EventNormalizationError:
        return _DISTANT_FUTURE


def analyze_fixture(path: Path, rules: list[LoadedRule]) -> FixtureRecord:
    try:
        records = list(read_records_as_dicts(path))
    except EvtxReadError as e:
        return FixtureRecord(
            name=path.name,
            behavior_hint=_behavior_hint(path.name),
            parsed_ok=False,
            parse_error=str(e),
            records_read=0,
            channels=[],
            providers=[],
            event_id_counts={},
            normalized_count=0,
            skipped_count=0,
            covered_count=0,
            uncovered_count=0,
            uncovered_breakdown=[],
            matched_rule_ids=[],
            matched_rule_titles=[],
            matched_technique_ids=[],
            alerts_created=0,
            incident_ids=[],
            mitre_technique_ids=[],
            detected=False,
            classification_codes=[1],
            classification_labels=[FAILURE_CATEGORIES[1]],
            reason=f"python-evtx failed to parse the file: {e}",
        )

    # -- raw inventory (straight off System, not the normalized schema --
    # Provider isn't promoted onto NormalizedEvent and doesn't need to be
    # for a reporting script) --
    channels: set[str] = set()
    providers: set[str] = set()
    event_id_counts: Counter[int] = Counter()
    for record in records:
        system = record.get("Event", {}).get("System", {})
        if not isinstance(system, dict):
            continue
        channel = system.get("Channel")
        if isinstance(channel, str) and channel:
            channels.add(channel)
        provider = system.get("Provider")
        if isinstance(provider, dict):
            name = provider.get("@Name")
            if isinstance(name, str) and name:
                providers.add(name)
        raw_eid = system.get("EventID")
        if isinstance(raw_eid, dict):
            raw_eid = raw_eid.get("#text")
        try:
            event_id_counts[int(raw_eid)] += 1
        except (TypeError, ValueError):
            pass

    # -- normalize + coverage + in-process detection (no DB) --
    covered_pairs = covered_event_ids(rules)
    normalized_count = 0
    skipped_count = 0
    covered_count = 0
    uncovered_counter: Counter[tuple[str | None, int]] = Counter()
    matched_rule_ids: set[str] = set()
    matched_titles: set[str] = set()
    matched_techniques: set[str] = set()

    for record in records:
        try:
            event = normalize_event(record)
        except EventNormalizationError:
            skipped_count += 1
            continue
        normalized_count += 1
        pair = (canonical_channel(event.channel), event.event_id)
        if pair in covered_pairs:
            covered_count += 1
        else:
            uncovered_counter[(event.channel, event.event_id)] += 1
        for match in evaluate_event(event, rules):
            matched_rule_ids.add(match.rule_id)
            matched_titles.add(match.title)
            if match.technique_id:
                matched_techniques.add(match.technique_id)

    # -- real persistence pass: fresh in-memory DB per fixture, sorted
    # ascending exactly like routes_ingest.py does before calling
    # ingest_records(matched_at=None) --
    SessionLocal = _make_session_factory()
    sorted_records = sorted(records, key=_timestamp_sort_key)
    with SessionLocal() as db:
        outcome = ingest_records(db, sorted_records, rules=rules, matched_at=None)
        # The in-process pass above (evaluate_event() only) is blind to the
        # sequence engine (detection/sequences.py) -- it runs only inside
        # ingest_records' own real path, after the per-event loop. Without
        # this merge, a sequence-only hit (found live 2026-09-05: the
        # Kerberos password spray fixture correctly showed 2 alerts/HIT,
        # but its "Rules matched" column silently showed only the
        # unrelated 1102 rule, dropping the sequence match this file was
        # actually built to verify) would never appear in the "Rules
        # matched" column even though outcome.alerts_created already
        # counted it.
        matched_titles.update(outcome.matched_rule_titles)
        for pattern in SEQUENCE_PATTERNS.values():
            if pattern.title in outcome.matched_rule_titles:
                matched_rule_ids.add(pattern.rule_id)
                if pattern.technique_id:
                    matched_techniques.add(pattern.technique_id)
        mitre_ids: set[str] = set()
        if outcome.incident_ids:
            incidents = db.query(Incident).filter(Incident.id.in_(outcome.incident_ids)).all()
            for incident in incidents:
                mitre_ids.update(incident.mitre_technique_ids or [])

    detected = outcome.alerts_created > 0

    # -- classification --
    canonical_channels_present = {canonical_channel(c) for c in channels}
    auto_codes: list[int] = []
    if not detected:
        if not channels or canonical_channels_present <= {None}:
            auto_codes.append(2)
        elif covered_count == 0:
            auto_codes.append(3)
        else:
            auto_codes.append(6)  # covered but no match -- rule missing/too narrow
        if skipped_count > 0:
            auto_codes.append(4)

    manual_review = False
    if detected:
        codes: list[int] = []
        reason = "detected -- " + ", ".join(sorted(matched_titles))
    else:
        override = KNOWN_MISS_CLASSIFICATION.get(path.name)
        if override:
            codes = list(override["categories"])  # type: ignore[arg-type]
            reason = str(override["reason"])
        else:
            codes = auto_codes or [11]
            reason = (
                "auto-classified from coverage/normalization facts only -- "
                "NOT yet manually verified against real field data; treat as "
                "provisional"
            )
            manual_review = True

    return FixtureRecord(
        name=path.name,
        behavior_hint=_behavior_hint(path.name),
        parsed_ok=True,
        parse_error=None,
        records_read=len(records),
        channels=sorted(channels),
        providers=sorted(providers),
        event_id_counts={str(k): v for k, v in sorted(event_id_counts.items())},
        normalized_count=normalized_count,
        skipped_count=skipped_count,
        covered_count=covered_count,
        uncovered_count=sum(uncovered_counter.values()),
        uncovered_breakdown=[
            {"channel": c, "event_id": e, "count": n}
            for (c, e), n in sorted(uncovered_counter.items(), key=lambda kv: -kv[1])
        ],
        matched_rule_ids=sorted(matched_rule_ids),
        matched_rule_titles=sorted(matched_titles),
        matched_technique_ids=sorted(matched_techniques),
        alerts_created=outcome.alerts_created,
        incident_ids=outcome.incident_ids,
        mitre_technique_ids=sorted(mitre_ids),
        detected=detected,
        correct_technique=_correct_technique(path.name, matched_techniques | mitre_ids),
        classification_codes=codes,
        classification_labels=[FAILURE_CATEGORIES[c] for c in codes],
        reason=reason,
        manual_review_needed=manual_review,
    )


def _write_markdown(records: list[FixtureRecord], out_path: Path) -> None:
    lines = [
        f"# NightOwl {len(records)}-fixture failure/capability matrix",
        "",
        "Generated by `scripts/build_failure_matrix.py` -- do not edit by hand. Rules + sequence detectors only; "
        "the ML anomaly layer is disabled here and evaluated separately (ML.md).",
        "",
        f"**{sum(1 for r in records if r.correct_technique)}/{len(records)} detected with the correct ATT&CK "
        f"technique; {sum(1 for r in records if r.detected)}/{len(records)} raised any alert** "
        "(every capture in detected/ and undetected/ is an attack capture).",
        "",
        "| Fixture | Behavior (from filename) | Channel(s) | Event IDs | Parsed | "
        "Normalized | Covered/Uncovered | Rules matched | Alerts | Incidents | "
        "MITRE | Status | Classification | Reason |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in sorted(records, key=lambda x: (x.detected, x.name)):
        status = "HIT" if r.correct_technique else "WRONG-TECHNIQUE" if r.detected else "MISS"
        classification = ", ".join(r.classification_labels) or "--"
        lines.append(
            "| {name} | {behavior} | {channels} | {eids} | {parsed} | {norm}/{skip} "
            "| {cov}/{uncov} | {rules} | {alerts} | {incidents} | {mitre} | {status} "
            "| {classification} | {reason} |".format(
                name=r.name,
                behavior=r.behavior_hint,
                channels="; ".join(r.channels) or "(none)",
                eids=", ".join(str(k) for k in r.event_id_counts) or "(none)",
                parsed="yes" if r.parsed_ok else f"NO ({r.parse_error})",
                norm=r.normalized_count,
                skip=r.skipped_count,
                cov=r.covered_count,
                uncov=r.uncovered_count,
                rules=", ".join(r.matched_rule_titles) or "--",
                alerts=r.alerts_created,
                incidents=len(r.incident_ids),
                mitre=", ".join(r.mitre_technique_ids) or "--",
                status=status,
                classification=classification,
                reason=r.reason.replace("|", "/").replace("\n", " "),
            )
        )
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    rules = get_loaded_rules()
    print(f"Loaded {len(rules)} detection rules")

    fixture_paths = sorted(p for d in MALICIOUS_DIRS for p in d.glob("*.evtx"))
    if not fixture_paths:
        print(f"No fixtures found in {MALICIOUS_DIRS}", file=sys.stderr)
        return 1

    print(f"Analyzing {len(fixture_paths)} fixtures (large files take a while)...")
    records: list[FixtureRecord] = []
    for i, path in enumerate(fixture_paths, start=1):
        print(f"  [{i}/{len(fixture_paths)}] {path.name} ...", flush=True)
        records.append(analyze_fixture(path, rules))

    detected = sum(1 for r in records if r.detected)
    misses = [r for r in records if not r.detected]

    print("\n" + "=" * 100)
    print(f"  Detected: {detected}/{len(records)}")
    print("=" * 100)

    # Cross-check the known-miss overrides against what this run actually
    # found -- if the rule set changed since those were verified, this
    # will loudly say so instead of silently trusting stale conclusions.
    actual_miss_names = {r.name for r in misses}
    known_names = set(KNOWN_MISS_CLASSIFICATION)
    if actual_miss_names != known_names:
        print("\n!! Miss set has changed since KNOWN_MISS_CLASSIFICATION was last verified:")
        for name in sorted(actual_miss_names - known_names):
            print(f"   + new miss, not yet classified by hand: {name}")
        for name in sorted(known_names - actual_miss_names):
            print(f"   - previously a miss, now detected (or file missing): {name}")

    needs_review = [r for r in misses if r.manual_review_needed]
    if needs_review:
        print(f"\n{len(needs_review)} miss(es) auto-classified only, need manual verification:")
        for r in needs_review:
            print(f"  - {r.name}: {r.classification_labels}")

    classification_counts: Counter[str] = Counter()
    for r in misses:
        for label in r.classification_labels:
            classification_counts[label] += 1
    print("\nMiss classification breakdown:")
    for label, count in classification_counts.most_common():
        print(f"  {label:32s} {count}")

    out_dir = Path(__file__).resolve().parent
    json_path = out_dir / "failure_matrix.json"
    md_path = out_dir / "failure_matrix.md"
    json_path.write_text(json.dumps([asdict(r) for r in records], indent=2), encoding="utf-8")
    _write_markdown(records, md_path)
    print(f"\nWrote {json_path}")
    print(f"Wrote {md_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
