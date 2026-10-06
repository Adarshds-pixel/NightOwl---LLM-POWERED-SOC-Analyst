"""Process-wide access to the trained anomaly detector.

The ingest path used to `joblib.load` the model on every request and wrap the
whole ML phase in a bare `except Exception`. That combination hid a real
deployment bug for weeks: the feature extractor lived in backend/scripts,
which neither .dockerignore nor the Dockerfile's COPY list includes, so in any
container build the import raised ModuleNotFoundError, the except swallowed
it, and the ML layer simply never ran -- silently, on every upload.

So: load once, and say plainly (once) whether the model is available.
"""

import logging
import threading
from pathlib import Path

from app.ml.detector import NightOwlAnomalyDetector

logger = logging.getLogger(__name__)

MODEL_PATH = Path(__file__).resolve().parent / "models" / "anomaly_detector.joblib"

_lock = threading.Lock()
_detector: NightOwlAnomalyDetector | None = None
_loaded = False


def get_detector() -> NightOwlAnomalyDetector | None:
    """The shared detector, or None if no usable model is on disk.

    A missing or unreadable model is a normal, non-fatal state -- ingest keeps
    working without the ML layer -- but it is logged once at WARNING so it is
    visible rather than inferred from the absence of ML alerts.
    """
    global _detector, _loaded

    if _loaded:
        return _detector

    with _lock:
        if _loaded:
            return _detector
        _loaded = True

        if not MODEL_PATH.exists():
            logger.warning(
                "ML anomaly detection disabled: no model at %s. "
                "Train one with scripts/train_ml_model.py.",
                MODEL_PATH,
            )
            return None

        detector = NightOwlAnomalyDetector()
        try:
            detector.load(str(MODEL_PATH))
        except Exception:
            logger.exception("ML anomaly detection disabled: failed to load %s", MODEL_PATH)
            return None

        if detector.feature_names is None:
            logger.warning(
                "ML anomaly detection disabled: %s predates feature-name binding "
                "and cannot be scored safely. Retrain with scripts/train_ml_model.py.",
                MODEL_PATH,
            )
            return None

        logger.info(
            "ML anomaly detector loaded (%d features, thresholds %.1f/%.1f)",
            len(detector.feature_names),
            detector.threshold_suspicious,
            detector.threshold_high,
        )
        _detector = detector
        return _detector


def reset_detector_cache() -> None:
    """Drop the cached detector. For tests that swap the model on disk."""
    global _detector, _loaded
    with _lock:
        _detector = None
        _loaded = False
