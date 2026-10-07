"""Train the ML anomaly layer: one model per log family on benign windows.

Source: sample_logs/real_world_fixtures/NightOwl-Benign-Dataset/ (tracked in
git, so a clone can reproduce the shipped model exactly). Add your own benign
captures with --extra-dir (e.g. logs collected with collect_benign_logs.ps1
from more machines -- the single most effective way to improve this layer).

Overlapping exports are de-duplicated by (host, channel, EventRecordID), then
cut into (host, family, 10-minute) windows; windows smaller than
MIN_WINDOW_EVENTS are not modelled (they are not scored in production either).
A family with fewer than MIN_TRAIN_WINDOWS windows gets no model -- the layer
simply does not score that family rather than score it badly.

    ./venv/Scripts/python.exe scripts/train_ml_model.py
    ./venv/Scripts/python.exe scripts/train_ml_model.py --extra-dir D:/benign_logs
"""

import argparse
import sys
from collections import defaultdict
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(BACKEND / "scripts"))

from app.ml.detector import MIN_TRAIN_WINDOWS, MIN_WINDOW_EVENTS, fit_family, new_bundle  # noqa: E402
from app.ml.features import FAMILIES, build_vocabulary  # noqa: E402
from app.ml.runtime import MODEL_PATH  # noqa: E402
from app.ml.windows import build_windows, dedupe  # noqa: E402
from run_detection_benchmark import load_events  # noqa: E402  (shared, cached EVTX parsing)

BENIGN_DIR = BACKEND / "sample_logs" / "real_world_fixtures" / "NightOwl-Benign-Dataset"


def benign_windows(dirs: list[Path]) -> dict[str, list[tuple[str, object, list]]]:
    """family -> [(host, window_start, events)] over every .evtx in `dirs`."""
    events = []
    for directory in dirs:
        for path in sorted(directory.glob("*.evtx")):
            file_events, _read, _skipped = load_events(path)
            events.extend(file_events)
    events = dedupe(sorted(events, key=lambda e: e.timestamp))
    by_family: dict[str, list] = defaultdict(list)
    for (host, family, start), window in build_windows(events).items():
        if len(window) >= MIN_WINDOW_EVENTS:
            by_family[family].append((host, start, window))
    for family in by_family:
        by_family[family].sort(key=lambda item: (item[0], item[1]))
    return by_family


def train(dirs: list[Path]):
    by_family = benign_windows(dirs)
    models, skipped = {}, {}
    for family in FAMILIES:
        items = by_family.get(family, [])
        if len(items) < MIN_TRAIN_WINDOWS:
            skipped[family] = f"{len(items)} windows (< {MIN_TRAIN_WINDOWS})"
            continue
        windows = [w for _h, _s, w in items]
        models[family] = fit_family(family, windows, [h for h, _s, _w in items], build_vocabulary(windows))
    return models, skipped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--extra-dir", type=Path, action="append", default=[], help="additional benign EVTX directory")
    args = parser.parse_args()

    dirs = [BENIGN_DIR, *args.extra_dir]
    models, skipped = train(dirs)
    if not models:
        print("No family had enough benign windows to model; nothing written.")
        return 1
    bundle = new_bundle(
        models,
        training_source=", ".join(str(d.relative_to(BACKEND)) if d.is_relative_to(BACKEND) else str(d) for d in dirs),
        notes={"skipped_families": skipped},
    )
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    bundle.save(MODEL_PATH)
    print(f"Wrote {MODEL_PATH}")
    for family, model in models.items():
        print(
            f"  {family:11} {model.train_windows:5d} windows from {', '.join(model.train_hosts)}; "
            f"{len(model.feature_names)} features ({len(model.dropped_features)} dropped); "
            f"thresholds medium {model.threshold_medium:.1f} / high {model.threshold_high:.1f}"
        )
    for family, reason in skipped.items():
        print(f"  {family:11} not modelled: {reason}")
    print("Thresholds are percentiles of TRAINING distances -- see scripts/eval_ml_model.py for held-out rates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
