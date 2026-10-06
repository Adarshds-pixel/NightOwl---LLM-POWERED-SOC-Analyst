"""GET /rules -- the running detection rule set, read-only.

The rules themselves are YAML files under `detection/rules/`, loaded and
cached by `detection/rule_loader.py`; until now nothing exposed them, so
the frontend's Rules Engine page had to hard-code "15 rules". This route
serialises the *actually loaded* rule set (so a malformed rule that got
skipped at load time correctly doesn't appear) and joins each rule to its
real firing history from the `alerts` table.

Read-only by design: rules are version-controlled files reviewed like
code, not rows a UI can toggle at runtime, so there is deliberately no
POST/PATCH/DELETE here and `enabled` reflects "this rule loaded and is in
the running set", not a user-flippable switch.

The ML anomaly layer (`app/ml/`) is appended as a built-in entry: it files
alerts under a rule_id with no YAML file behind it, so it would otherwise
be a live detector missing from the list its own alerts point at.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.ml.rule import ML_ANOMALY_RULE
from app.ml.runtime import get_detector
from app.detection.rule_loader import get_loaded_rules
from app.services.rule_service import get_rule_activity

router = APIRouter()


class RuleInfo(BaseModel):
    rule_id: str
    title: str
    description: str
    level: str
    category: str | None
    technique_id: str | None
    tactics: list[str]
    condition: str
    selections: list[str]
    author: str
    date: str
    status: str
    references: list[str]
    filename: str
    enabled: bool
    match_count: int
    matches_24h: int
    last_triggered: datetime | None


class RuleListResponse(BaseModel):
    rules: list[RuleInfo]
    count: int
    total: int


def _build_rules(db: Session) -> list[RuleInfo]:
    """The loaded rule set joined to its firing history, unfiltered.
    Shared by both routes so the single-rule view can't drift from the
    list view (and so neither has to call the other's route function,
    whose defaults are FastAPI Query objects rather than plain values).
    """
    activity = get_rule_activity(db)
    return [
        RuleInfo(
            rule_id=rule.rule_id,
            title=rule.title,
            description=rule.description,
            level=rule.level,
            category=rule.category,
            technique_id=rule.technique_id,
            tactics=rule.tactics,
            condition=rule.condition,
            selections=sorted(rule.detections.keys()),
            author=rule.author,
            date=rule.date,
            status=rule.status,
            references=rule.references,
            filename=rule.yaml_path.replace("\\", "/").rsplit("/", 1)[-1],
            # Every rule the loader returns is part of the running rule
            # set; a skipped/malformed file simply isn't here at all.
            enabled=True,
            match_count=activity[rule.rule_id].match_count if rule.rule_id in activity else 0,
            matches_24h=activity[rule.rule_id].matches_24h if rule.rule_id in activity else 0,
            last_triggered=activity[rule.rule_id].last_triggered if rule.rule_id in activity else None,
        )
        for rule in get_loaded_rules()
    ] + [_ml_rule_info(activity)]


def _ml_rule_info(activity) -> RuleInfo:
    """The ML anomaly layer as a read-only built-in entry in the rule list.

    It creates alerts under a rule_id (`ml-anomaly-detector`) but has no YAML
    file, so without this the Rules page omitted a live detector entirely and
    `GET /rules/ml-anomaly-detector` 404'd on an id the alerts list was
    already showing.

    The empty structural fields are honest, not placeholders: this detector
    has no Sigma condition, no selections, and no logsource category, because
    it is not a Sigma rule. `enabled` reflects whether a trained model is
    actually on disk -- it is the one entry in this list that can be present
    but inactive.
    """
    detector = get_detector()
    return RuleInfo(
        rule_id=ML_ANOMALY_RULE.rule_id,
        title=ML_ANOMALY_RULE.title,
        description=ML_ANOMALY_RULE.description,
        level=ML_ANOMALY_RULE.level,
        category=None,
        technique_id=ML_ANOMALY_RULE.technique_id,
        tactics=ML_ANOMALY_RULE.tactics,
        condition="",
        selections=[],
        author="NightOwl",
        date="",
        status="stable",
        references=["ML.md"],
        filename="app/ml/detector.py",
        enabled=detector is not None,
        match_count=activity[ML_ANOMALY_RULE.rule_id].match_count
        if ML_ANOMALY_RULE.rule_id in activity else 0,
        matches_24h=activity[ML_ANOMALY_RULE.rule_id].matches_24h
        if ML_ANOMALY_RULE.rule_id in activity else 0,
        last_triggered=activity[ML_ANOMALY_RULE.rule_id].last_triggered
        if ML_ANOMALY_RULE.rule_id in activity else None,
    )


@router.get("/rules", response_model=RuleListResponse)
def get_rules(
    technique_id: str | None = Query(default=None, description="exact MITRE technique id, e.g. T1059.001"),
    level: str | None = Query(default=None, description="sigma level: informational|low|medium|high|critical"),
    category: str | None = Query(default=None, description="logsource category, e.g. process_creation"),
    db: Session = Depends(get_db),
) -> RuleListResponse:
    rows = _build_rules(db)

    filtered = rows
    if technique_id is not None:
        wanted = technique_id.upper()
        filtered = [r for r in filtered if (r.technique_id or "").upper() == wanted]
    if level is not None:
        filtered = [r for r in filtered if r.level == level.lower()]
    if category is not None:
        filtered = [r for r in filtered if (r.category or "") == category]

    return RuleListResponse(rules=filtered, count=len(filtered), total=len(rows))


@router.get("/rules/{rule_id}", response_model=RuleInfo)
def get_rule(rule_id: str, db: Session = Depends(get_db)) -> RuleInfo:
    for rule in _build_rules(db):
        if rule.rule_id == rule_id:
            return rule
    raise HTTPException(status_code=404, detail=f"rule {rule_id} not found")
