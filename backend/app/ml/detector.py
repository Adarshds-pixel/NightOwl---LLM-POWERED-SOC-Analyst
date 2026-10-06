"""Unsupervised behavioural anomaly detector (Ledoit-Wolf Mahalanobis).

Fits a shrunk covariance estimate over log1p'd 10-minute host-window feature
vectors drawn strictly from benign telemetry, then scores unseen windows by
Mahalanobis distance. Thresholds are percentiles of the *training* distances,
so they describe the baseline's own spread -- they are not a measured
false-positive rate. See scripts/eval_ml_model.py for the host-held-out
evaluation.

Two invariants this module enforces, both learned the hard way:

* **Feature identity travels with the model.** The vector order used to be the
  dict insertion order of extract_features(), stored nowhere. Reordering one
  line in that function would have silently corrupted every score. The fitted
  feature names are persisted and checked on every call.

* **Features without baseline support are refused.** Mahalanobis distance is
  scale-free: a feature the benign corpus barely exercises gets a near-zero
  variance, so its first ordinary value in production reads as an
  astronomically large deviation. On the 2-host benign corpus this was not a
  corner case -- 31 of 70 features never fired at all, and `network_event_count`
  fired in 6 windows out of 1829, which was enough to make a host with normal
  web traffic score ~17,000 against a ~400 threshold. train() drops such
  columns rather than shipping a model that flags any host unlike the baseline.
"""

import logging
import os

import joblib
import numpy as np
from sklearn.covariance import LedoitWolf

logger = logging.getLogger(__name__)

# Below this, a feature carries no usable baseline and is dropped at fit time.
MIN_TRAIN_VARIANCE = 1e-9

# A feature must also be non-zero in at least this fraction of benign windows.
# Variance alone is too weak a test: six non-zero windows out of 1829 clears
# `var > 0` comfortably while still leaving the column effectively degenerate.
# The benign corpus has a clean gap here -- features sit at either <=0.71% or
# >=1.64% support, nothing between.
MIN_TRAIN_SUPPORT = 0.01


class NightOwlAnomalyDetector:
    def __init__(self, random_state=42):
        # Ledoit-Wolf shrinkage keeps the covariance invertible across
        # correlated, highly skewed volumetric features.
        self.model = LedoitWolf()
        self.is_trained = False
        self.threshold_suspicious = None
        self.threshold_high = None
        self.feature_names: list[str] | None = None
        self.dropped_features: list[str] = []

    def train(self, features: np.ndarray, feature_names: list[str] | None = None):
        """Fit on benign feature vectors and derive the severity thresholds.

        Columns the benign set cannot support -- constant, or non-zero in fewer
        than MIN_TRAIN_SUPPORT of windows -- are dropped and recorded in
        `dropped_features`; the surviving names become this model's schema.
        """
        features = np.asarray(features, dtype=float)
        if feature_names is not None and len(feature_names) != features.shape[1]:
            raise ValueError(
                f"feature_names has {len(feature_names)} entries but the matrix has "
                f"{features.shape[1]} columns"
            )

        # Log1p transform to handle highly skewed volumetric data
        features_log = np.log1p(features)

        has_variance = features_log.var(axis=0) > MIN_TRAIN_VARIANCE
        has_support = (features != 0).mean(axis=0) >= MIN_TRAIN_SUPPORT
        keep = has_variance & has_support
        if not keep.any():
            raise ValueError(
                "no feature has enough benign support to model; the baseline corpus is too narrow"
            )

        if feature_names is not None:
            self.dropped_features = [n for n, k in zip(feature_names, keep, strict=True) if not k]
            self.feature_names = [n for n, k in zip(feature_names, keep, strict=True) if k]
        else:
            self.dropped_features = []
            self.feature_names = None

        if (~keep).any():
            logger.warning(
                "dropping %d unsupported feature(s) from the model: %s",
                int((~keep).sum()),
                ", ".join(self.dropped_features) or "unnamed columns",
            )

        features_log = features_log[:, keep]

        self.model.fit(features_log)
        self.is_trained = True

        # Percentiles of the TRAINING distances. This is a property of the
        # baseline, not a held-out false-positive rate -- do not quote it as one.
        distances = self.model.mahalanobis(features_log)
        self.threshold_suspicious = float(np.percentile(distances, 99.5))
        self.threshold_high = float(np.percentile(distances, 99.9))

    def save(self, filepath: str):
        """Serialize the trained model to disk."""
        if not self.is_trained:
            raise RuntimeError("Cannot save an untrained model.")
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump({
            "model": self.model,
            "threshold_suspicious": self.threshold_suspicious,
            "threshold_high": self.threshold_high,
            "feature_names": self.feature_names,
            "dropped_features": self.dropped_features,
        }, filepath)

    def load(self, filepath: str):
        """Load a previously trained model."""
        data = joblib.load(filepath)
        if not (isinstance(data, dict) and "model" in data):
            # Pre-Ledoit-Wolf IsolationForest artifacts stored a bare estimator
            # and no thresholds. There is no sane distance threshold to invent
            # for one, so refuse rather than score every window as anomalous.
            raise ValueError(
                f"{filepath} is not a NightOwl detector bundle (no thresholds); "
                "retrain with scripts/train_ml_model.py"
            )
        self.model = data["model"]
        self.threshold_suspicious = data["threshold_suspicious"]
        self.threshold_high = data["threshold_high"]
        self.feature_names = data.get("feature_names")
        self.dropped_features = data.get("dropped_features", [])
        self.is_trained = True

    def select(self, features: dict) -> np.ndarray:
        """Build this model's input vector from a full extract_features() dict.

        Honours the fitted schema, so a model trained before a new feature was
        added keeps working instead of silently mis-scoring.
        """
        if self.feature_names is None:
            raise RuntimeError("this model has no feature schema; retrain to bind one")
        missing = [n for n in self.feature_names if n not in features]
        if missing:
            raise KeyError(f"feature(s) missing from extraction: {missing}")
        return np.array([[float(features[n]) for n in self.feature_names]])

    def score_window(self, features: np.ndarray) -> list[dict]:
        """Score one or more feature vectors.

        Returns a list with one entry per input row: a normalized score
        (0.0-1.0, higher = more anomalous), a severity band, and the raw
        Mahalanobis distance.
        """
        if not self.is_trained:
            raise RuntimeError("Cannot score with an untrained model.")

        features = np.asarray(features, dtype=float)
        fitted = getattr(self.model, "location_", None)
        if fitted is not None and features.shape[1] != fitted.shape[0]:
            raise ValueError(
                f"model was fitted on {fitted.shape[0]} features but got "
                f"{features.shape[1]}; use detector.select(extract_features(window))"
            )

        # Log1p transform
        features_log = np.log1p(features)

        distances = self.model.mahalanobis(features_log)

        results = []
        for dist in distances:
            # Simple severity mapping based on derived thresholds
            if dist >= self.threshold_high:
                severity = "High"
                # Map to [0.68, 1.0] with a soft ceiling
                excess = dist - self.threshold_high
                norm_score = min(1.0, 0.68 + (excess / self.threshold_high) * 0.32)
            elif dist >= self.threshold_suspicious:
                severity = "Medium"
                # Map to [0.55, 0.68)
                ratio = (dist - self.threshold_suspicious) / (
                    self.threshold_high - self.threshold_suspicious
                )
                norm_score = 0.55 + ratio * 0.13
            else:
                severity = "Low"
                # Map to [0.0, 0.55)
                ratio = dist / self.threshold_suspicious
                norm_score = ratio * 0.54

            results.append({
                "anomaly_score": float(norm_score),
                "severity": severity,
                "raw_distance": float(dist),
            })

        return results
