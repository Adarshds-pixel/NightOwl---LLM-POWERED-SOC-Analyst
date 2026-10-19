"""Detection-rule activity aggregates for `GET /rules` (Vol1 §3.4
layering: routes -> services -> models/db).

The rule *definitions* live on disk and are loaded by
`detection/rule_loader.py`; this module only answers "how often has each
of them actually fired?" by aggregating the `alerts` table, which stores
the Sigma `rule_id` of every match. Kept out of the route so the query
shape stays testable on its own, matching event_service/incident_service.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ml.rule import ML_RULE_ID
from app.models.alert import Alert


@dataclass(frozen=True)
class RuleActivity:
    match_count: int
    matches_24h: int
    last_triggered: datetime | None


def get_rule_activity(db: Session, now: datetime | None = None) -> dict[str, RuleActivity]:
    """{rule_id: RuleActivity} for every rule that has ever matched.

    Two grouped queries rather than one per rule, so the cost is constant
    in the number of rules. Rules that have never fired are simply absent
    from the mapping -- the caller (which already holds the full loaded
    rule set) fills in zeros, so a brand-new rule file still shows up.

    `now` anchors the "last 24h" window and defaults to the most recent
    `Alert.matched_at` in the whole dataset, not real wall-clock time.
    Alerts are timestamped from each event's own historical time
    (ingest_service.py's `matched_at=None` path -- see its docstring), and
    this project's real workload is batch-ingesting historical/public
    malware-sample EVTX captures (dated 2019-2021 in practice), not a live
    forwarder. Anchoring to real `datetime.now()` would make "matches in
    the last 24h" permanently read 0 for every such import, no matter what
    was just ingested, since wall-clock "now" is always years ahead of
    every alert. Anchoring to the dataset's own latest activity keeps the
    metric meaningful for a historical import while still meaning exactly
    "the real last 24 hours" the moment there's a genuinely recent alert --
    which is what an actual live deployment would naturally have.

    The anchor is the latest rule or sequence detection; ML anomaly records
    are advisory and only anchor the window when nothing else exists. Found
    19 Oct 2026: an ML record dated months after every detection pushed the
    window past all of them, so "Triggered 24h" read 0.
    """
    if now is None:
        latest = db.execute(
            select(func.max(Alert.matched_at)).where(Alert.rule_id != ML_RULE_ID)
        ).scalar() or db.execute(select(func.max(Alert.matched_at))).scalar()
        now = latest or datetime.now(timezone.utc)
        if now.tzinfo is None:
            # SQLite (the in-memory test DB) strips tzinfo on round-trip;
            # every Alert.matched_at is written as UTC (ingest_service.py
            # always deals in aware UTC datetimes), so this is a display
            # correction, not a guess.
            now = now.replace(tzinfo=timezone.utc)
    cutoff = now - timedelta(hours=24)

    totals = db.execute(
        select(Alert.rule_id, func.count(Alert.id), func.max(Alert.matched_at)).group_by(Alert.rule_id)
    ).all()
    recent = dict(
        db.execute(
            select(Alert.rule_id, func.count(Alert.id)).where(Alert.matched_at >= cutoff).group_by(Alert.rule_id)
        ).all()
    )

    return {
        rule_id: RuleActivity(
            match_count=count,
            matches_24h=int(recent.get(rule_id, 0)),
            last_triggered=last,
        )
        for rule_id, count, last in totals
    }
