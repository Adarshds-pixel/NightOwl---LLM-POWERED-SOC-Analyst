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

Two kinds of detector have no YAML file but still file alerts under their own
rule_id, so they are listed too, each tagged with `kind` so a client never
mistakes them for Sigma rules: the multi-event sequence detectors
(`kind="sequence"`, detection/sequences.py) and the ML anomaly layer
(`kind="ml"`, app/ml/). Every alert's rule_id therefore resolves here.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.ml.rule import ML_ANOMALY_RULE
from app.ml.runtime import get_detector
from app.detection.rule_loader import get_loaded_rules
from app.detection.sequences import SEQUENCE_PATTERNS
from app.services.rule_service import get_rule_activity

router = APIRouter()


# Plain-language summaries of the sequence detectors (they have no YAML
# description field to read one from).
_SEQUENCE_DESCRIPTIONS = {
    "sequence-process-herpaderping": (
        "Correlates, within one upload, a process writing an executable, opening the process it spawned "
        "from it, and that child loading its own image -- the observable shape of Process Herpaderping."
    ),
    "sequence-smb-share-enum-probe": (
        "Correlates an inbound SMB (445) connection with a connect to the Server service (srvsvc) named "
        "pipe from the same source shortly after -- remote share enumeration."
    ),
    "sequence-kerberos-password-spray": (
        "Several distinct accounts failing Kerberos pre-authentication from one source address within a "
        "short window -- password spraying."
    ),
}


class RuleInfo(BaseModel):
    rule_id: str
    # "sigma" (a YAML rule), "sequence" (a multi-event correlation in
    # detection/sequences.py) or "ml" (the anomaly model).
    kind: str = "sigma"
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
    ] + [_sequence_rule_info(pattern, activity) for pattern in SEQUENCE_PATTERNS.values()] + [
        _ml_rule_info(activity)
    ]


def _activity_fields(rule_id: str, activity) -> dict:
    entry = activity.get(rule_id)
    return {
        "match_count": entry.match_count if entry else 0,
        "matches_24h": entry.matches_24h if entry else 0,
        "last_triggered": entry.last_triggered if entry else None,
    }


def _sequence_rule_info(pattern, activity) -> RuleInfo:
    return RuleInfo(
        rule_id=pattern.rule_id,
        kind="sequence",
        title=pattern.title,
        description=_SEQUENCE_DESCRIPTIONS.get(pattern.rule_id, ""),
        level=pattern.level,
        category=None,
        technique_id=pattern.technique_id,
        tactics=list(pattern.tactics),
        condition="",
        selections=[],
        author="NightOwl",
        date="",
        status="experimental",
        references=[],
        filename="app/detection/sequences.py",
        enabled=True,
        **_activity_fields(pattern.rule_id, activity),
    )


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
        kind="ml",
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
        **_activity_fields(ML_ANOMALY_RULE.rule_id, activity),
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
