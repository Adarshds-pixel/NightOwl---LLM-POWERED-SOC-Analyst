"""Held-out evaluation of the ML anomaly layer (per-family models).

Every number here comes from windows the scoring model never saw.

  A. Within-host temporal split -- the deployment condition. For each
     family, each host's windows are split chronologically (first 70% train,
     last 30% test); a model is fitted on all hosts' training parts and its
     thresholds re-derived from them. Reported: held-out benign windows
     flagged, and that as alerts per host-day (a host producing a window
     every 10 minutes yields 144 windows/day).
  B. Leave-one-host-out -- transfer to an unseen machine of a known kind.
  C. Unseen benign captures -- the shipped model scored against benign data
     outside its training set: the local-only captures in
     real_world_fixtures/benign/ (if present), the synthetic noise fixtures,
     and the mislabeled attack capture bits_openvpn.evtx.
  D. Attack captures -- every attack fixture, cut into windows exactly as a
     single-file upload would be. Most are far smaller than
     MIN_WINDOW_EVENTS and are therefore NOT scored: the ML layer is a
     volumetric/behavioural signal, and single-event attacks are the rules'
     job. Reported: how many attack windows were scorable and how many of
     those were flagged.

    ./venv/Scripts/python.exe scripts/eval_ml_model.py [--json out.json]
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(BACKEND / "scripts"))

from app.ml.detector import MIN_TRAIN_WINDOWS, MIN_WINDOW_EVENTS, fit_family, new_bundle  # noqa: E402
from app.ml.features import FAMILIES, build_vocabulary  # noqa: E402
from app.ml.runtime import MODEL_PATH  # noqa: E402
from app.ml.detector import AnomalyModelBundle  # noqa: E402
from app.ml.windows import build_windows, dedupe  # noqa: E402
from run_detection_benchmark import ATTACK_DIRS, GROUND_TRUTH, load_events  # noqa: E402
from train_ml_model import BENIGN_DIR, benign_windows  # noqa: E402

WINDOWS_PER_DAY = 144


def _flagged(bundle, family, windows) -> int:
    return sum(1 for w in windows if (s := bundle.score(family, w)) is not None and s.severity != "low")


def protocol_a(by_family) -> dict:
    out = {}
    for family, items in by_family.items():
        per_host = defaultdict(list)
        for host, start, w in items:
            per_host[host].append((start, w))
        train, test = [], []
        for host, rows in per_host.items():
            rows.sort(key=lambda r: r[0])
            cut = int(len(rows) * 0.7)
            train += [(host, w) for _s, w in rows[:cut]]
            test += [(host, w) for _s, w in rows[cut:]]
        if len(train) < MIN_TRAIN_WINDOWS or not test:
            out[family] = {"skipped": f"{len(train)} train / {len(test)} test windows"}
            continue
        windows = [w for _h, w in train]
        model = fit_family(family, windows, [h for h, _w in train], build_vocabulary(windows))
        bundle = new_bundle({family: model}, "eval")
        flagged = _flagged(bundle, family, [w for _h, w in test])
        out[family] = {
            "test_windows": len(test),
            "flagged": flagged,
            "flag_rate": flagged / len(test),
            "alerts_per_host_day": flagged / len(test) * WINDOWS_PER_DAY,
        }
    return out


def protocol_b(by_family) -> dict:
    out = {}
    for family, items in by_family.items():
        hosts = sorted({h for h, _s, _w in items})
        results = {}
        for held_out in hosts:
            train = [(h, w) for h, _s, w in items if h != held_out]
            test = [w for h, _s, w in items if h == held_out]
            if len(train) < MIN_TRAIN_WINDOWS or not test:
                results[held_out] = {"skipped": f"{len(train)} train windows"}
                continue
            windows = [w for _h, w in train]
            model = fit_family(family, windows, [h for h, _w in train], build_vocabulary(windows))
            flagged = _flagged(new_bundle({family: model}, "eval"), family, test)
            results[held_out] = {"test_windows": len(test), "flagged": flagged, "flag_rate": flagged / len(test)}
        out[family] = results
    return out


def _file_windows(paths) -> dict[str, list]:
    by_family = defaultdict(list)
    for path in paths:
        events, _r, _s = load_events(path)
        for (_host, family, _start), w in build_windows(dedupe(events)).items():
            by_family[family].append((path.name, w))
    return by_family


def protocol_c(bundle) -> dict:
    real = BACKEND / "sample_logs" / "real_world_fixtures"
    sources = {
        "local benign captures (unseen)": sorted((real / "benign").glob("*.evtx")),
        "synthetic noise (unseen)": sorted((BACKEND / "sample_logs" / "demo_fixtures").glob("noise_*.evtx")),
        "mislabeled bits_openvpn (benign)": [p for d in ATTACK_DIRS for p in d.glob("bits_openvpn.evtx")],
    }
    out = {}
    for label, paths in sources.items():
        scored = flagged = 0
        examples = []
        for family, items in _file_windows(paths).items():
            for name, w in items:
                s = bundle.score(family, w)
                if s is None:
                    continue
                scored += 1
                if s.severity != "low":
                    flagged += 1
                    if len(examples) < 5:
                        examples.append({"file": name, "family": family, "distance": round(s.distance, 1),
                                         "top": [f["feature"] for f in s.top_features]})
        out[label] = {"files": len(paths), "scored_windows": scored, "flagged": flagged,
                      "flag_rate": flagged / scored if scored else None, "examples": examples}
    return out


def protocol_d(bundle) -> dict:
    paths = [p for d in ATTACK_DIRS for p in sorted(d.glob("*.evtx"))
             if GROUND_TRUTH.get(p.name, {}).get("split") != "excluded"]
    total = scored = flagged = 0
    captures_flagged = []
    for name_family_items in [_file_windows([p]) for p in paths]:
        for family, items in name_family_items.items():
            for name, w in items:
                total += 1
                s = bundle.score(family, w)
                if s is None:
                    continue
                scored += 1
                if s.severity != "low":
                    flagged += 1
                    captures_flagged.append(name)
    return {"attack_windows": total, "scorable_windows": scored, "flagged": flagged,
            "recall_on_scorable": flagged / scored if scored else None,
            "captures_flagged": sorted(set(captures_flagged))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()

    by_family = benign_windows([BENIGN_DIR])
    by_family = {f: items for f, items in by_family.items() if f in FAMILIES}
    bundle = AnomalyModelBundle.load(MODEL_PATH)
    report = {
        "min_window_events": MIN_WINDOW_EVENTS,
        "A_within_host_temporal": protocol_a(by_family),
        "B_leave_one_host_out": protocol_b(by_family),
        "C_unseen_benign": protocol_c(bundle),
        "D_attack_captures": protocol_d(bundle),
    }
    print(json.dumps(report, indent=2, default=str))
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
