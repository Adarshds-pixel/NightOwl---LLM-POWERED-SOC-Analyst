"""Unsupervised behavioural anomaly detector: one Ledoit-Wolf Mahalanobis
model per log family, fitted on benign windows only.

Scoring a window yields its Mahalanobis distance from the family's benign
baseline (on log1p features) and a per-feature attribution: the distance is
z^T P z, so feature i contributes z_i (P z)_i. The top contributors are
stored on the alert so an analyst sees WHY a window was flagged ("12 failed
logons vs a baseline median of 0"), not just a score.

Invariants enforced here:
  * feature identity travels with the model -- every family stores its own
    ordered feature names and event-id vocabulary, and scoring refuses a
    vector it was not fitted on;
  * features without benign support are dropped at fit time (a column that
    is ~always zero has near-zero variance, so its first non-zero value
    would read as an astronomically large deviation);
  * the bundle records the scikit-learn version that produced it and is
    refused under a different one -- unpickling an estimator across sklearn
    versions is not guaranteed to work;
  * windows smaller than MIN_WINDOW_EVENTS are never scored: a handful of
    events is not "behaviour", and single-event attacks are the rules' job.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

import joblib
import numpy as np
import sklearn
from sklearn.covariance import LedoitWolf

from app.ml.features import extract_features, novel_event_ids
from app.schemas.event import NormalizedEvent

logger = logging.getLogger(__name__)

BUNDLE_FORMAT = 2
MIN_WINDOW_EVENTS = 10
MIN_TRAIN_WINDOWS = 30
MIN_TRAIN_VARIANCE = 1e-9
MIN_TRAIN_SUPPORT = 0.02
TOP_CONTRIBUTORS = 3


class ModelCompatibilityError(RuntimeError):
    pass


@dataclass
class FamilyModel:
    family: str
    vocabulary: list[int]
    feature_names: list[str]
    dropped_features: list[str]
    seen_event_ids: list[int]
    covariance: LedoitWolf
    baseline_median: dict[str, float]
    threshold_medium: float
    threshold_high: float
    train_windows: int
    train_hosts: list[str]

    def vector(self, features: dict[str, float]) -> np.ndarray:
        missing = [n for n in self.feature_names if n not in features]
        if missing:
            raise KeyError(f"{self.family}: feature(s) missing from extraction: {missing}")
        return np.log1p(np.array([[max(0.0, float(features[n])) for n in self.feature_names]]))

    def explain(self, x: np.ndarray, features: dict[str, float]) -> list[dict]:
        z = x[0] - self.covariance.location_
        contributions = z * (self.covariance.precision_ @ z)
        order = np.argsort(contributions)[::-1][:TOP_CONTRIBUTORS]
        return [
            {
                "feature": self.feature_names[i],
                "value": float(features[self.feature_names[i]]),
                "baseline_median": float(self.baseline_median.get(self.feature_names[i], 0.0)),
                "share": float(contributions[i] / max(contributions.sum(), 1e-9)),
            }
            for i in order
            if contributions[i] > 0
        ]


@dataclass
class AnomalyScore:
    family: str
    distance: float
    severity: str  # "high" | "medium" | "low"
    threshold_medium: float
    threshold_high: float
    top_features: list[dict]
    novel_event_ids: list[int]
    window_events: int


@dataclass
class AnomalyModelBundle:
    families: dict[str, FamilyModel]
    sklearn_version: str
    created_at: str
    training_source: str
    format: int = BUNDLE_FORMAT
    notes: dict = field(default_factory=dict)

    def score(self, family: str, events: list[NormalizedEvent]) -> AnomalyScore | None:
        """None when this family has no model or the window is too small."""
        model = self.families.get(family)
        if model is None or len(events) < MIN_WINDOW_EVENTS:
            return None
        features = extract_features(family, events, model.vocabulary)
        x = model.vector(features)
        distance = float(model.covariance.mahalanobis(x)[0])
        if distance >= model.threshold_high:
            severity = "high"
        elif distance >= model.threshold_medium:
            severity = "medium"
        else:
            severity = "low"
        return AnomalyScore(
            family=family,
            distance=distance,
            severity=severity,
            threshold_medium=model.threshold_medium,
            threshold_high=model.threshold_high,
            top_features=model.explain(x, features) if severity != "low" else [],
            novel_event_ids=novel_event_ids(events, set(model.seen_event_ids)),
            window_events=len(events),
        )

    def save(self, path) -> None:
        joblib.dump(self, path, compress=3)

    @staticmethod
    def load(path) -> "AnomalyModelBundle":
        bundle = joblib.load(path)
        if not isinstance(bundle, AnomalyModelBundle) or getattr(bundle, "format", None) != BUNDLE_FORMAT:
            raise ModelCompatibilityError(f"{path} is not a format-{BUNDLE_FORMAT} NightOwl model bundle; retrain")
        if bundle.sklearn_version != sklearn.__version__:
            raise ModelCompatibilityError(
                f"{path} was trained with scikit-learn {bundle.sklearn_version} but {sklearn.__version__} is "
                "installed; retrain with scripts/train_ml_model.py (or install the matching version)"
            )
        return bundle


def fit_family(
    family: str,
    windows: list[list[NormalizedEvent]],
    hosts: list[str],
    vocabulary: list[int],
    medium_percentile: float = 99.5,
    high_percentile: float = 99.9,
) -> FamilyModel:
    """Fit one family's model on benign windows (already filtered to
    >= MIN_WINDOW_EVENTS). Thresholds are percentiles of the training
    distances -- a property of the baseline; held-out false-positive rates
    come from scripts/eval_ml_model.py."""
    if len(windows) < MIN_TRAIN_WINDOWS:
        raise ValueError(f"{family}: only {len(windows)} benign windows -- not enough to model")
    rows = [extract_features(family, w, vocabulary) for w in windows]
    names = list(rows[0].keys())
    raw = np.array([[r[n] for n in names] for r in rows], dtype=float)
    logged = np.log1p(raw)
    keep = (logged.var(axis=0) > MIN_TRAIN_VARIANCE) & ((raw != 0).mean(axis=0) >= MIN_TRAIN_SUPPORT)
    if not keep.any():
        raise ValueError(f"{family}: no feature has enough benign support")
    kept = [n for n, k in zip(names, keep) if k]
    dropped = [n for n, k in zip(names, keep) if not k]
    covariance = LedoitWolf().fit(logged[:, keep])
    distances = covariance.mahalanobis(logged[:, keep])
    return FamilyModel(
        family=family,
        vocabulary=vocabulary,
        feature_names=kept,
        dropped_features=dropped,
        seen_event_ids=sorted({e.event_id for w in windows for e in w}),
        covariance=covariance,
        baseline_median={n: float(np.median(raw[:, names.index(n)])) for n in kept},
        threshold_medium=float(np.percentile(distances, medium_percentile)),
        threshold_high=float(np.percentile(distances, high_percentile)),
        train_windows=len(windows),
        train_hosts=sorted(set(hosts)),
    )


def new_bundle(families: dict[str, FamilyModel], training_source: str, notes: dict | None = None) -> AnomalyModelBundle:
    return AnomalyModelBundle(
        families=families,
        sklearn_version=sklearn.__version__,
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        training_source=training_source,
        notes=notes or {},
    )
