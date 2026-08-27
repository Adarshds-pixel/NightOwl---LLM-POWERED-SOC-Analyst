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
    """
    now = now or datetime.now(timezone.utc)
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
