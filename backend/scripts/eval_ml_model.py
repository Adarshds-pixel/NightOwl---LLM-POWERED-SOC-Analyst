"""Host-held-out evaluation of the ML anomaly layer.

Replaces scripts/eval/evaluate_model.py and scratch_prod_eval.py, both of which
scored the benign half of the dataset with a model that had been fitted on
exactly those rows -- and whose threshold was the 99.5th percentile of those
same distances. "0.5% of benign windows flagged" was therefore arithmetic, not
a measurement, and the precision and accuracy derived from it were inflated.

What this script does differently:

* Benign windows are split BY HOST. Fit on one host, measure the benign false
  positive rate on the other, then swap. A random split leaks badly here --
  consecutive 10-minute windows from one machine are near-duplicates.
* The percentile threshold is re-derived inside each fold, from that fold's
  training distances only.
* Attack windows are scored by both folds' models (they share no host with the
  benign corpus), and the results are pooled.
* Accuracy is reported next to the majority-class baseline, because with ~1829
  benign and ~87 attack windows a model that never fires already scores 95.6%.
* PR-AUC is reported because it is the threshold-independent number, and
  because precision/recall at one arbitrary percentile hides the trade-off.

Usage:
    python scripts/eval_ml_model.py              # uses the cached attack matrix
    python scripts/eval_ml_model.py --rebuild    # re-parse the attack EVTX corpus
"""

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.ingestion.evtx_reader import read_records_as_dicts
from app.ingestion.normalizer import normalize_events
from app.ml.detector import NightOwlAnomalyDetector
from app.ml.features import extract_features

SCRIPTS_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPTS_DIR.parent
BENIGN_CSV = SCRIPTS_DIR / "ml_features.csv"
ATTACK_CACHE = SCRIPTS_DIR / "eval" / "attack_features_70.csv"

# bits_openvpn.evtx sits in the `undetected` attack folder but contains 1,537
# Microsoft-Windows-Bits-Client events from routine Windows Update / Google
# Update / OneDrive polling and zero malicious or OpenVPN traces. The dataset
# pipeline labels every window in an attack capture `is_attack = 1`, so its 190
# benign windows were being counted as false negatives. Excluding it is a
# correction to the ground truth, not a convenience -- documented in ML.md §3,
# and named here so the exclusion is visible wherever the metrics are produced.
MISLABELED_CAPTURES = ("bits_openvpn",)

PERCENTILES = (99.0, 99.5, 99.9)
IDENTIFIER_COLUMNS = ("host", "window_start", "is_attack")


def load_benign():
    """Return (X, hosts, starts, feature_names) for the benign baseline corpus."""
    X, hosts, starts, names = [], [], [], None
    with open(BENIGN_CSV, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            hosts.append((row.get("host") or "").upper())
            starts.append(row.get("window_start") or "")
            for key in IDENTIFIER_COLUMNS:
                row.pop(key, None)
            if names is None:
                names = list(row.keys())
            X.append([float(row[n]) for n in names])
    return np.array(X), np.array(hosts), np.array(starts), names


def build_attack(feature_names):
    """Parse the attack EVTX corpus into a feature matrix and cache it."""
    fixtures = BACKEND_DIR / "sample_logs" / "real_world_fixtures"
    files = sorted(fixtures.glob("detected/*.evtx")) + sorted(fixtures.glob("undetected/*.evtx"))

    rows = []
    skipped = []
    for path in files:
        if any(tag in path.name.lower() for tag in MISLABELED_CAPTURES):
            skipped.append(path.name)
            continue
        windows = defaultdict(list)
        for record in read_records_as_dicts(path):
            if not record:
                continue
            try:
                for event in normalize_events([record]):
                    floored = (event.timestamp.minute // 10) * 10
                    bucket = event.timestamp.replace(minute=floored, second=0, microsecond=0)
                    windows[(event.host, bucket)].append(event)
            except Exception:
                continue
        for events in windows.values():
            if events:
                feats = extract_features(events)
                rows.append([float(feats[n]) for n in feature_names])

    print(f"Parsed {len(files) - len(skipped)} attack files -> {len(rows)} windows")
    if skipped:
        print(f"Excluded as mislabeled (see MISLABELED_CAPTURES): {', '.join(skipped)}")

    ATTACK_CACHE.parent.mkdir(parents=True, exist_ok=True)
    with open(ATTACK_CACHE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(feature_names)
        writer.writerows(rows)
    return np.array(rows)


def load_attack(feature_names, rebuild=False):
    if rebuild or not ATTACK_CACHE.exists():
        return build_attack(feature_names)
    with open(ATTACK_CACHE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if list(reader.fieldnames or []) != list(feature_names):
            print("Cached attack matrix has a stale schema; rebuilding.")
            return build_attack(feature_names)
        rows = [[float(r[n]) for n in feature_names] for r in reader]
    print(f"Loaded {len(rows)} attack windows from cache ({ATTACK_CACHE.name})")
    return np.array(rows)


def confusion(y_true, y_pred):
    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    tn = int(np.sum((y_pred == 0) & (y_true == 0)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))
    return tp, tn, fp, fn


def report(label, y_true, scores, threshold):
    y_pred = (scores >= threshold).astype(int)
    tp, tn, fp, fn = confusion(y_true, y_pred)
    acc = (tp + tn) / len(y_true)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    baseline = max(np.mean(y_true == 0), np.mean(y_true == 1))
    print(f"  {label}")
    print(f"    TP {tp:4d}  TN {tn:5d}  FP {fp:3d}  FN {fn:3d}")
    print(
        f"    Precision {prec * 100:6.2f}%   Recall {rec * 100:6.2f}%   F1 {f1 * 100:6.2f}%"
    )
    print(
        f"    Accuracy  {acc * 100:6.2f}%   (majority-class baseline "
        f"{baseline * 100:.2f}% -- accuracy is near-meaningless at this class ratio)"
    )
    return {"precision": prec, "recall": rec, "f1": f1}


def evaluate_split(name, X_train, X_test_benign, X_attack, feature_names):
    """Fit on X_train, score held-out benign + attack, print every threshold."""
    detector = NightOwlAnomalyDetector()
    detector.train(X_train, feature_names)
    keep = [feature_names.index(n) for n in detector.feature_names]

    train_dist = detector.model.mahalanobis(np.log1p(X_train[:, keep]))
    benign_scores = detector.model.mahalanobis(np.log1p(X_test_benign[:, keep]))
    attack_scores = detector.model.mahalanobis(np.log1p(X_attack[:, keep]))

    scores = np.concatenate([benign_scores, attack_scores])
    labels = np.concatenate([np.zeros(len(benign_scores)), np.ones(len(attack_scores))])

    print()
    print(f"--- {name} ---")
    print(f"  Fitted on {len(detector.feature_names)}/{len(feature_names)} features "
          f"({len(detector.dropped_features)} lacked benign support)")
    print(f"  Train {len(X_train)} | held-out benign {len(benign_scores)} | attack {len(attack_scores)}")
    print(f"  PR-AUC (threshold-free): {average_precision_score(labels, scores):.4f}"
          f"   [random baseline {labels.mean():.4f}]")

    out = {}
    for p in PERCENTILES:
        threshold = float(np.percentile(train_dist, p))
        report(f"threshold = {p}th percentile of training distances ({threshold:.1f})",
               labels, scores, threshold)
        out[p] = (scores, labels, threshold)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rebuild", action="store_true", help="re-parse the attack EVTX corpus")
    args = parser.parse_args()

    X_benign, hosts, starts, feature_names = load_benign()
    X_attack = load_attack(feature_names, rebuild=args.rebuild)

    unique_hosts = sorted(set(hosts))
    print()
    print(f"Benign: {len(X_benign)} windows across {len(unique_hosts)} host(s): ", end="")
    print(", ".join(f"{h} ({int(np.sum(hosts == h))})" for h in unique_hosts))
    print(f"Attack: {len(X_attack)} windows")
    if len(unique_hosts) < 2:
        print("WARNING: only one benign host -- a host-held-out split is not possible.")
        return

    # ------------------------------------------------------------------
    # Protocol A -- within-host temporal split. This is the deployment
    # condition: the baseline covers the host being monitored, and the
    # question is whether LATER windows from that same host read as normal.
    # Split chronologically, never randomly: consecutive 10-minute windows
    # from one machine are near-duplicates, so a random split leaks.
    # ------------------------------------------------------------------
    print()
    print("=" * 72)
    print("PROTOCOL A -- WITHIN-HOST TEMPORAL SPLIT  (the deployment condition)")
    print("Fit on each host's first 70% of windows by time, score its last 30%")
    print("plus all attack windows. Threshold re-derived from the training part.")
    print("=" * 72)

    pooled_a = {p: {"scores": [], "labels": [], "thresholds": []} for p in PERCENTILES}
    for host in unique_hosts:
        idx = np.where(hosts == host)[0]
        idx = idx[np.argsort(starts[idx])]
        cut = int(len(idx) * 0.7)
        if cut < 50 or len(idx) - cut < 20:
            print(f"\n--- {host}: too few windows to split ({len(idx)}); skipped ---")
            continue
        folds = evaluate_split(
            f"{host}: train on first {cut} windows / test on last {len(idx) - cut}",
            X_benign[idx[:cut]], X_benign[idx[cut:]], X_attack, feature_names,
        )
        for p, (s, l, t) in folds.items():
            pooled_a[p]["scores"].append(s)
            pooled_a[p]["labels"].append(l)
            pooled_a[p]["thresholds"].append(t)

    # ------------------------------------------------------------------
    # Protocol B -- host-held-out. A much harder ask, and a different
    # question: can a baseline from one machine describe a different kind of
    # machine? Reported because it bounds how far a single-host baseline
    # transfers, not because it is how the system would be deployed.
    # ------------------------------------------------------------------
    print()
    print("=" * 72)
    print("PROTOCOL B -- HOST-HELD-OUT  (transfer to an unseen machine)")
    print("Fit on one benign host, score the other host entirely. Pessimistic:")
    print("in deployment the baseline would include the host being monitored.")
    print("=" * 72)

    pooled_b = {p: {"scores": [], "labels": [], "thresholds": []} for p in PERCENTILES}
    for held_out in unique_hosts:
        train_mask = hosts != held_out
        folds = evaluate_split(
            f"train on {', '.join(h for h in unique_hosts if h != held_out)} / test on {held_out}",
            X_benign[train_mask], X_benign[~train_mask], X_attack, feature_names,
        )
        for p, (s, l, t) in folds.items():
            pooled_b[p]["scores"].append(s)
            pooled_b[p]["labels"].append(l)
            pooled_b[p]["thresholds"].append(t)

    for title, pooled in (("PROTOCOL A (within-host temporal)", pooled_a),
                          ("PROTOCOL B (host-held-out)", pooled_b)):
        if not pooled[PERCENTILES[0]]["scores"]:
            continue
        print()
        print("=" * 72)
        print(f"POOLED -- {title}")
        print("Every benign window scored by a model that never saw it.")
        print("=" * 72)
        for p in PERCENTILES:
            scores = np.concatenate(pooled[p]["scores"])
            labels = np.concatenate(pooled[p]["labels"])
            # Each fold has its own threshold; compare each block against its own.
            preds = np.concatenate([
                (s >= t).astype(int)
                for s, t in zip(pooled[p]["scores"], pooled[p]["thresholds"], strict=True)
            ])
            tp, tn, fp, fn = confusion(labels, preds)
            prec = tp / (tp + fp) if (tp + fp) else 0.0
            rec = tp / (tp + fn) if (tp + fn) else 0.0
            f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
            benign_fp_rate = fp / (fp + tn) if (fp + tn) else 0.0
            print()
            print(f"  {p}th percentile threshold")
            print(f"    TP {tp:4d}  TN {tn:5d}  FP {fp:4d}  FN {fn:4d}")
            print(f"    Precision {prec * 100:6.2f}%   Recall {rec * 100:6.2f}%   F1 {f1 * 100:6.2f}%")
            print(f"    Held-out benign false-positive rate: {benign_fp_rate * 100:.3f}%")
            print(f"    PR-AUC: {average_precision_score(labels, scores):.4f}"
                  f"   [random baseline {labels.mean():.4f}]")

    print()
    print("Quote recall, F1, PR-AUC and the held-out benign FP rate, and say which")
    print("protocol they came from. Do NOT quote accuracy without the")
    print("majority-class baseline beside it.")


if __name__ == "__main__":
    main()
