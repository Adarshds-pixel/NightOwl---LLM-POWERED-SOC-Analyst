"""Live SOC replay -- turns real captured Sysmon telemetry into a paced,
"happening now" demo feed. See app/demo/ for the rebasing/scenario logic
and app/services/{replay_service,demo_service}.py for the DB-touching
implementation; this router only translates that into HTTP.

Gated behind `require_demo_mode` in addition to the usual `require_api_key`
-- `POST /demo/reset` is destructive, and a deployment that is not meant to
demo itself (settings.demo_mode_enabled=False) should not expose it at all,
not merely rely on the shared API key being set.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.demo.scenario_loader import ScenarioLoadError, get_loaded_scenarios
from app.services import audit_service, demo_service, replay_service
from app.services.replay_service import ReplayAlreadyRunningError, ReplayRun

router = APIRouter()


def require_demo_mode() -> None:
    if not settings.demo_mode_enabled:
        raise HTTPException(status_code=403, detail="demo mode is disabled on this deployment")


class ScenarioSegmentInfo(BaseModel):
    id: str
    title: str
    kind: str
    source_capture: str
    record_count: int
    expected_rule_titles: list[str]
    expected_technique_ids: list[str]


class ScenarioInfo(BaseModel):
    id: str
    title: str
    description: str
    host: str
    window_minutes: float
    duration_seconds: float
    segments: list[ScenarioSegmentInfo]


class ScenarioListResponse(BaseModel):
    scenarios: list[ScenarioInfo]


class ReplayStartRequest(BaseModel):
    scenario_id: str = "demo_shift"
    reset_first: bool = True


class ReplayStatusResponse(BaseModel):
    run_id: str | None
    scenario_id: str | None
    scenario_title: str | None
    state: str
    started_at: datetime | None
    finished_at: datetime | None
    duration_seconds: float
    window_minutes: float
    elapsed_seconds: float
    records_emitted: int
    records_total: int
    events_ingested: int
    alerts_created: int
    incident_ids: list[int]
    matched_rule_titles: list[str]
    current_segment_id: str | None
    error: str | None


class DemoResetResponse(BaseModel):
    deleted: dict[str, int]


def _to_status(run: ReplayRun | None) -> ReplayStatusResponse:
    if run is None:
        return ReplayStatusResponse(
            run_id=None,
            scenario_id=None,
            scenario_title=None,
            state="idle",
            started_at=None,
            finished_at=None,
            duration_seconds=0,
            window_minutes=0,
            elapsed_seconds=0,
            records_emitted=0,
            records_total=0,
            events_ingested=0,
            alerts_created=0,
            incident_ids=[],
            matched_rule_titles=[],
            current_segment_id=None,
            error=None,
        )

    now = run.finished_at or datetime.now(timezone.utc)
    elapsed = max(0.0, (now - run.started_at).total_seconds())

    return ReplayStatusResponse(
        run_id=run.run_id,
        scenario_id=run.scenario_id,
        scenario_title=run.scenario_title,
        state=run.state,
        started_at=run.started_at,
        finished_at=run.finished_at,
        duration_seconds=run.duration_seconds,
        window_minutes=run.window_minutes,
        elapsed_seconds=min(elapsed, run.duration_seconds),
        records_emitted=run.records_emitted,
        records_total=run.records_total,
        events_ingested=run.events_ingested,
        alerts_created=run.alerts_created,
        incident_ids=run.incident_ids,
        matched_rule_titles=run.matched_rule_titles,
        current_segment_id=run.current_segment_id,
        error=run.error,
    )


@router.get("/demo/scenarios", response_model=ScenarioListResponse)
def get_demo_scenarios() -> ScenarioListResponse:
    scenarios = get_loaded_scenarios()
    return ScenarioListResponse(
        scenarios=[
            ScenarioInfo(
                id=scenario.id,
                title=scenario.title,
                description=scenario.description,
                host=scenario.host,
                window_minutes=scenario.window_minutes,
                duration_seconds=scenario.duration_seconds,
                segments=[
                    ScenarioSegmentInfo(
                        id=segment.id,
                        title=segment.title,
                        kind=segment.kind,
                        source_capture=segment.source_capture,
                        record_count=segment.record_count,
                        expected_rule_titles=segment.expected_rule_titles,
                        expected_technique_ids=segment.expected_technique_ids,
                    )
                    for segment in scenario.segments
                ],
            )
            for scenario in scenarios
        ]
    )


@router.post("/demo/replay/start", response_model=ReplayStatusResponse)
def start_replay(payload: ReplayStartRequest, db: Session = Depends(get_db)) -> ReplayStatusResponse:
    if payload.reset_first:
        demo_service.reset_demo_data(db)

    try:
        run = replay_service.start_replay(payload.scenario_id)
    except ReplayAlreadyRunningError as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    except ScenarioLoadError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    return _to_status(run)


@router.get("/demo/replay/status", response_model=ReplayStatusResponse)
def get_replay_status() -> ReplayStatusResponse:
    return _to_status(replay_service.get_current_run())


@router.post("/demo/replay/stop", response_model=ReplayStatusResponse)
def stop_replay() -> ReplayStatusResponse:
    return _to_status(replay_service.stop_replay())


@router.post("/demo/reset", response_model=DemoResetResponse)
def reset_demo(db: Session = Depends(get_db)) -> DemoResetResponse:
    current = replay_service.get_current_run()
    if current is not None and current.state == "running":
        raise HTTPException(status_code=409, detail="cannot reset while a replay is running -- stop it first")

    deleted = demo_service.reset_demo_data(db)
    # Recorded after the delete commits, not before -- audit_log is one of
    # the tables being wiped, so a pre-reset entry would just be erased by
    # its own reset.
    audit_service.record_event(db, entity_type="demo", entity_id=0, action="reset", details=deleted)

    return DemoResetResponse(deleted=deleted)
