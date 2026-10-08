"""GET /ml/model -- what the anomaly layer was trained on and how well it did.

The console's "ML model" panel (Settings) reads this so the experimental layer
can be inspected instead of taken on trust: the mode it runs in, when and on
which machines it was trained, its thresholds, and the false-alarm rates
measured on held-out benign data (scripts/ml_eval_results.json, written by
eval_ml_model.py). It never scores anything and exposes no event data.
"""

import json
from pathlib import Path

from fastapi import APIRouter
from pydantic import BaseModel

from app.core.config import settings
from app.ml.runtime import get_detector, get_detector_status

router = APIRouter()

EVAL_RESULTS_PATH = Path(__file__).resolve().parents[2] / "scripts" / "ml_eval_results.json"

ADVISORY_EXPLANATION = (
    "Advisory mode: unusual windows of activity are recorded with the features behind them, but they never open "
    "or change an incident and are never counted as detections. The model learned what normal looks like from a "
    "small number of machines, so it also flags ordinary activity on machines it has not seen."
)


class HeldOutResult(BaseModel):
    test_windows: int
    flagged: int
    alerts_per_host_day: float


class FamilyInfo(BaseModel):
    family: str
    train_windows: int
    train_hosts: list[str]
    features_fitted: int
    features_dropped: int
    threshold_medium: float
    threshold_high: float
    held_out: HeldOutResult | None = None


class MlModelResponse(BaseModel):
    mode: str
    ready: bool
    detail: str
    trained_at: str | None = None
    training_source: str | None = None
    min_window_events: int | None = None
    families: list[FamilyInfo] = []
    explanation: str = ADVISORY_EXPLANATION


def _held_out() -> tuple[dict[str, HeldOutResult], int | None]:
    try:
        data = json.loads(EVAL_RESULTS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}, None
    results: dict[str, HeldOutResult] = {}
    for family, row in (data.get("A_within_host_temporal") or {}).items():
        if isinstance(row, dict) and "test_windows" in row:
            results[family] = HeldOutResult(
                test_windows=row["test_windows"],
                flagged=row["flagged"],
                alerts_per_host_day=round(row["alerts_per_host_day"], 1),
            )
    return results, data.get("min_window_events")


@router.get("/ml/model", response_model=MlModelResponse)
def ml_model() -> MlModelResponse:
    ready, detail = get_detector_status()
    bundle = get_detector()
    if settings.ml_mode == "off":
        return MlModelResponse(mode="off", ready=False, detail="disabled (ML_MODE=off)")
    if bundle is None:
        return MlModelResponse(mode=settings.ml_mode, ready=False, detail=detail)
    held_out, min_events = _held_out()
    families = [
        FamilyInfo(
            family=name,
            train_windows=model.train_windows,
            train_hosts=sorted(model.train_hosts),
            features_fitted=len(model.feature_names),
            features_dropped=len(model.dropped_features),
            threshold_medium=round(model.threshold_medium, 1),
            threshold_high=round(model.threshold_high, 1),
            held_out=held_out.get(name),
        )
        for name, model in sorted(bundle.families.items())
    ]
    return MlModelResponse(
        mode=settings.ml_mode,
        ready=ready,
        detail=detail,
        trained_at=bundle.created_at,
        training_source=bundle.training_source,
        min_window_events=min_events,
        families=families,
        explanation=ADVISORY_EXPLANATION
        if settings.ml_mode == "advisory"
        else "Alert mode: unusual windows may open incidents (still without an ATT&CK technique).",
    )
