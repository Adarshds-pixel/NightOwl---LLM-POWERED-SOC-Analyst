"""CLI: fit the Ledoit-Wolf anomaly detector on the benign feature matrix.

Reads scripts/ml_features.csv (produced by extract_ml_features.py) and writes
app/ml/models/anomaly_detector.joblib.

Features with no variance across the benign corpus are dropped by
detector.train() and reported here. That is not a tuning knob: a feature the
baseline never exercises has only the shrinkage floor as variance, so its
first non-zero value on a real host scores as an enormous deviation. Keeping
them is what made the 70-feature model flag any host with ordinary network
traffic.
"""

import csv
import sys
from pathlib import Path

import numpy as np

# Adjust sys.path to import from backend.app
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.ml.detector import NightOwlAnomalyDetector

IDENTIFIER_COLUMNS = ("host", "window_start", "is_attack")


def load_features(csv_path: str):
    """Return (X, feature_names, identifiers) from a feature CSV."""
    features = []
    identifiers = []
    feature_names = None

    with open(csv_path, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            identifiers.append({k: row.get(k) for k in IDENTIFIER_COLUMNS if k in row})
            for key in IDENTIFIER_COLUMNS:
                row.pop(key, None)
            if feature_names is None:
                feature_names = list(row.keys())
            features.append([float(row[name]) for name in feature_names])

    return np.array(features), (feature_names or []), identifiers


def main():
    features_csv = Path(__file__).resolve().parent / "ml_features.csv"
    if not features_csv.exists():
        print(f"Error: {features_csv} not found. Run extract_ml_features.py first.")
        sys.exit(1)

    print(f"Loading features from {features_csv}...")
    X, feature_names, _ = load_features(str(features_csv))
    print(f"Loaded {X.shape[0]} windows with {X.shape[1]} features.")

    if X.shape[0] == 0:
        print("Error: No data loaded. Cannot train model.")
        sys.exit(1)

    print("Training Ledoit-Wolf Mahalanobis detector...")
    detector = NightOwlAnomalyDetector()
    detector.train(X, feature_names)

    model_path = Path(__file__).resolve().parent.parent / "app" / "ml" / "models" / "anomaly_detector.joblib"
    detector.save(str(model_path))

    print(f"Model successfully saved to {model_path}")
    print(f"Features fitted : {len(detector.feature_names)}")
    print(f"Features dropped: {len(detector.dropped_features)} (insufficient benign support)")
    for name in detector.dropped_features:
        print(f"  - {name}")
    print(f"Derived Threshold Suspicious (99.5th %ile): {detector.threshold_suspicious:.4f}")
    print(f"Derived Threshold High (99.9th %ile): {detector.threshold_high:.4f}")
    print(
        "\nNote: those thresholds are percentiles of the TRAINING distances. "
        "For held-out metrics run scripts/eval_ml_model.py."
    )


if __name__ == "__main__":
    main()
