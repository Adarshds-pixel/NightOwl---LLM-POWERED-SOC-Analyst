"""Process-wide access to the trained anomaly model bundle.

Loaded once, lazily. A missing, incompatible (different scikit-learn) or
unreadable bundle is a normal, non-fatal state -- ingest keeps working
without the ML layer -- but the reason is logged once and reported by
GET /system/status, so "no ML alerts" is never mistaken for "nothing
anomalous".
"""

import logging
import threading
from pathlib import Path

from app.ml.detector import AnomalyModelBundle, ModelCompatibilityError

logger = logging.getLogger(__name__)

MODEL_PATH = Path(__file__).resolve().parent / "models" / "anomaly_detector.joblib"

_lock = threading.Lock()
_bundle: AnomalyModelBundle | None = None
_status: str = "not loaded yet"
_loaded = False


def get_detector() -> AnomalyModelBundle | None:
    global _bundle, _status, _loaded
    if _loaded:
        return _bundle
    with _lock:
        if _loaded:
            return _bundle
        _loaded = True
        if not MODEL_PATH.exists():
            _status = "no model file -- run scripts/train_ml_model.py"
            logger.warning("ML anomaly layer disabled: %s", _status)
            return None
        try:
            _bundle = AnomalyModelBundle.load(MODEL_PATH)
        except ModelCompatibilityError as exc:
            _status = str(exc)
            logger.warning("ML anomaly layer disabled: %s", _status)
            return None
        except Exception as exc:  # noqa: BLE001 -- a corrupt file must not take ingest down
            _status = f"model could not be loaded ({type(exc).__name__})"
            logger.exception("ML anomaly layer disabled: failed to load %s", MODEL_PATH)
            return None
        families = ", ".join(sorted(_bundle.families))
        _status = f"{families} models, trained {str(_bundle.created_at)[:10]}"
        logger.info("ML anomaly layer %s", _status)
        return _bundle


def get_detector_status() -> tuple[bool, str]:
    """(ready, human-readable detail) for GET /system/status."""
    bundle = get_detector()
    return bundle is not None, _status


def reset_detector_cache() -> None:
    """Drop the cached bundle. For tests that swap the model on disk."""
    global _bundle, _status, _loaded
    with _lock:
        _bundle = None
        _status = "not loaded yet"
        _loaded = False
