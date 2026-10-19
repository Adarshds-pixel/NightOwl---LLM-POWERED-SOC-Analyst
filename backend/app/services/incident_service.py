"""Groups related alerts into incidents (Day 9): same host, within a
GROUPING_WINDOW of each other, reuse the same open incident instead of
creating a new one per alert -- mirrors event_service.py/detection_service.py's
create/save layering (routes -> services -> models/db).

The `mitre_technique_ids` merge in find_or_create_incident below already
satisfies Day 11's "roll up technique IDs from an incident's alerts" --
no separate Day 11 change needed here, see docs/decisions.md.

Day 12 adds the two read paths behind `GET /incidents` and
`GET /incidents/{id}` (api/routes_incidents.py): `list_incidents` (filtered,
newest first) and `get_incident_alerts_with_events` (an incident's alerts
joined to their originating event, for the detail view).
"""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.detection.engine import RuleMatch
from app.detection.rule_loader import get_loaded_rules
from app.detection.sequences import SEQUENCE_PATTERNS
from app.detection.synthetic import NON_YAML_RULES
from app.mitre.loader import load_mitre_techniques
from app.ml.rule import ML_RULE_ID
from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import Incident
from app.services import event_service, severity_service

logger = logging.getLogger(__name__)

GROUPING_WINDOW = timedelta(hours=1)

# An analyst moving an incident to "investigating" must not make the next
# related alert spawn a parallel incident; only resolved/closed incidents
# stop absorbing new activity.
ACTIVE_STATUSES = ("open", "investigating")

INCIDENT_TITLE_MAX = 500

# Evidence-first alerts (pending.md item 5): a narrow window around an
# alert's own event, not the full 1h GROUPING_WINDOW incidents are grouped
# on -- "what else happened right around this" is investigative context,
# not every event this incident's grouping window happens to span.
RELATED_EVENTS_WINDOW = timedelta(minutes=5)
RELATED_EVENTS_LIMIT = 5


# Cover-up techniques (ATT&CK v19 T1685 family: an audit log cleared, an audit
# policy weakened). An attacker does these *around* the real attack, and they
# are rated high, so in the 10 Oct 2026 fixture audit seven incidents were
# headlined "Security Audit Log Cleared" while the attack itself (sAMAccountName
# spoofing, pass-the-hash, a remote SAM dump...) sat in the tags. A cover-up
# detection still raises severity and adds its technique, but it only names the
# incident when nothing else is in it.
COVER_UP_TECHNIQUE_PREFIX = "T1685"


def _is_cover_up(match: RuleMatch) -> bool:
    return bool(match.technique_id) and match.technique_id.startswith(COVER_UP_TECHNIQUE_PREFIX)


def _rule_behind_title(title: str):
    """The rule or sequence pattern an incident is currently titled after
    (titles are always "<rule title> on <host>", see _incident_title), or None
    for a title this code did not write. Longest rule title wins, so one rule
    title being a prefix of another cannot pick the wrong one."""
    candidates = [*get_loaded_rules(), *NON_YAML_RULES.values()]
    matching = [rule for rule in candidates if title.startswith(f"{rule.title} on ")]
    return max(matching, key=lambda rule: len(rule.title), default=None)


def _new_match_takes_title(existing: Incident, match: RuleMatch) -> bool:
    current = _rule_behind_title(existing.title)
    if current is None:
        return match.score > existing.severity_score
    current_is_cover_up = bool(current.technique_id) and current.technique_id.startswith(COVER_UP_TECHNIQUE_PREFIX)
    if _is_cover_up(match) != current_is_cover_up:
        # a real attack always replaces a cover-up headline; a cover-up never
        # replaces a real attack's
        return current_is_cover_up
    # Compared with the titling rule's own score, not the incident's: the
    # incident's score may have been raised by a cover-up that does not hold
    # the title, and a stronger real detection must still be able to take it.
    return match.score > severity_service.compute_severity_score(current.level, current.tactics)


def _incident_title(match: RuleMatch, host: str) -> str:
    title = f"{match.title} on {host}"
    return title if len(title) <= INCIDENT_TITLE_MAX else title[: INCIDENT_TITLE_MAX - 1] + "\u2026"


def _as_aware(value: datetime) -> datetime:
    # SQLite (tests) hands timezone-aware columns back naive; stored values are UTC.
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def find_or_create_incident(
    db: Session,
    host: str,
    matched_at: datetime,
    match: RuleMatch,
    *,
    advisory: bool = False,
    create: bool = True,
) -> Incident | None:
    """Merges this match into the active incident for `host` whose activity
    span [created_at, last_activity_at] lies within GROUPING_WINDOW of
    `matched_at`, or creates a new incident. Does not commit -- the caller
    controls the transaction boundary.

    The window slides with the incident's latest alert (last_activity_at), so
    one attack lasting longer than an hour stays one incident, and an
    earlier-timestamped match (an older file uploaded later) extends
    created_at backwards instead of landing in a different incident.

    On merge: technique id added if new; severity raised to the higher of the
    two; and when the new match is the most severe so far, the title follows
    it, so an incident never stays titled after a low-severity first alert
    while holding a critical one. Cover-up detections (a cleared log) are the
    exception: they never headline an incident that also holds the attack
    itself (see _new_match_takes_title).

    `advisory=True` (the ML anomaly layer) attaches to an existing incident
    without changing its title, severity or techniques. `create=False`
    returns None instead of opening a new incident when none covers that
    host and time (the ML layer's default advisory mode).
    """
    last_activity = func.coalesce(Incident.last_activity_at, Incident.created_at)
    existing = db.scalars(
        select(Incident)
        .where(Incident.host == host)
        .where(Incident.status.in_(ACTIVE_STATUSES))
        .where(Incident.created_at <= matched_at + GROUPING_WINDOW)
        .where(last_activity >= matched_at - GROUPING_WINDOW)
        .order_by(last_activity.desc(), Incident.id.desc())
    ).first()

    if existing is not None:
        created = _as_aware(existing.created_at)
        last = _as_aware(existing.last_activity_at or existing.created_at)
        stamp = _as_aware(matched_at)
        if stamp < created:
            existing.created_at = matched_at
        if stamp > last:
            existing.last_activity_at = matched_at
        elif existing.last_activity_at is None:
            existing.last_activity_at = existing.created_at
        if advisory:
            return existing
        if match.technique_id and match.technique_id not in existing.mitre_technique_ids:
            existing.mitre_technique_ids = [*existing.mitre_technique_ids, match.technique_id]
        if _new_match_takes_title(existing, match):
            existing.title = _incident_title(match, host)
            # The titling detection's technique leads the list, so every view
            # that shows "the" technique (the incident list, the evidence's
            # technique_id) names the same attack as the title. Found 19 Oct
            # 2026: a "Remote SAM Dump" incident listed T1685.005 (log clear).
            if match.technique_id:
                existing.mitre_technique_ids = [
                    match.technique_id,
                    *(t for t in existing.mitre_technique_ids if t != match.technique_id),
                ]
        existing.severity =severity_service.higher_severity(existing.severity, match.level)
        existing.severity_score = max(existing.severity_score, match.score)
        return existing

    if not create:
        return None

    incident = Incident(
        title=_incident_title(match, host),
        status="open",
        severity=match.level,
        severity_score=match.score,
        mitre_technique_ids=[match.technique_id] if match.technique_id else [],
        created_at=matched_at,
        last_activity_at=matched_at,
        host=host,
    )
    db.add(incident)
    db.flush()  # assign incident.id without committing the whole transaction yet
    logger.info("created incident %d for host %s", incident.id, host)
    return incident


def incident_cache_key(db: Session, incident: Incident) -> tuple[int, str]:
    """Key for cached explain/chat results: the incident id PLUS a
    fingerprint of the evidence they were generated from.

    Keyed on the id alone, a cached explanation survived new alerts merging
    into the incident (it described evidence that was no longer complete),
    and after a demo reset -- which restarts id sequences -- a brand-new
    incident #1 was served the previous run's incident #1 text.
    """
    alert_count, last_alert_id = db.execute(
        select(func.count(Alert.id), func.max(Alert.id)).where(Alert.incident_id == incident.id)
    ).one()
    created = incident.created_at.isoformat() if incident.created_at else ""
    fingerprint = f"{incident.host}|{created}|{incident.title}|{incident.severity}|{alert_count}|{last_alert_id}"
    return incident.id, fingerprint


def _filtered_incidents_stmt(
    severity: str | None,
    status: str | None,
    start_date: datetime | None,
    end_date: datetime | None,
    q: str | None = None,
):
    """Shared by list_incidents and count_incidents so the two never drift
    out of sync -- every filter is optional and additive (AND'd together).
    `q` is a case-insensitive substring match on title/host, backing the
    frontend's global search; same LIKE-not-full-text reasoning as
    event_service._filtered_events_stmt.
    """
    stmt = select(Incident)
    if q:
        pattern = f"%{q.strip()}%"
        stmt = stmt.where(or_(Incident.title.ilike(pattern), Incident.host.ilike(pattern)))
    if severity is not None:
        stmt = stmt.where(Incident.severity == severity)
    if status is not None:
        stmt = stmt.where(Incident.status == status)
    if start_date is not None:
        stmt = stmt.where(Incident.created_at >= start_date)
    if end_date is not None:
        stmt = stmt.where(Incident.created_at <= end_date)
    return stmt


def list_incidents(
    db: Session,
    severity: str | None = None,
    status: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    q: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> list[Incident]:
    """Newest-first incident list for `GET /incidents`, filtered by any
    combination of severity/status/created_at date range, with optional
    limit/offset pagination (Day 13). `limit=None` (the default for direct
    callers) returns every match, unpaginated; the route always passes an
    explicit limit.
    """
    # id as the tiebreaker: incidents can share created_at, and without a
    # total order Postgres may return different rows per page.
    stmt = _filtered_incidents_stmt(severity, status, start_date, end_date, q).order_by(
        Incident.created_at.desc(), Incident.id.desc()
    )
    if limit is not None:
        stmt = stmt.limit(limit).offset(offset)
    return list(db.scalars(stmt))


def count_incidents(
    db: Session,
    severity: str | None = None,
    status: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    q: str | None = None,
) -> int:
    """Total incidents matching the same filters as list_incidents, ignoring
    limit/offset -- lets `GET /incidents` report a page-independent `total`
    (Day 13) alongside the page of results.
    """
    subq = _filtered_incidents_stmt(severity, status, start_date, end_date, q).subquery()
    return db.scalar(select(func.count()).select_from(subq)) or 0


def get_incident_alerts_with_events(db: Session, incident_id: int) -> list[tuple[Alert, Event]]:
    """An incident's alerts joined to the event each one fired on, for
    `GET /incidents/{id}`'s detail view -- avoids a separate query per alert
    to fetch its event.
    """
    stmt = (
        select(Alert, Event)
        .join(Event, Alert.event_id == Event.id)
        .where(Alert.incident_id == incident_id)
        .order_by(Alert.matched_at, Alert.id)
    )
    return [(alert, event) for alert, event in db.execute(stmt)]


def get_related_events(db: Session, host: str, around: datetime, exclude_event_id: int) -> list[Event]:
    """Up to RELATED_EVENTS_LIMIT other events on `host` within
    RELATED_EVENTS_WINDOW of `around` (an alert's own event timestamp) --
    the investigative context an analyst would otherwise only get by
    switching to the Logs page and filtering by hand. Reuses
    event_service.list_events() (the same query GET /events runs) rather
    than a new query shape, per this item's "no new subsystem" scope.
    """
    # The nearest neighbours on BOTH sides of the alert. Taking the newest N
    # in the +/-5 min window (the previous behaviour) systematically dropped
    # the events just before the alert -- usually the ones that caused it.
    before = list(
        db.scalars(
            select(Event)
            .where(Event.host == host, Event.id != exclude_event_id)
            .where(Event.timestamp >= around - RELATED_EVENTS_WINDOW, Event.timestamp <= around)
            .order_by(Event.timestamp.desc(), Event.id.desc())
            .limit(RELATED_EVENTS_LIMIT)
        )
    )
    after = list(
        db.scalars(
            select(Event)
            .where(Event.host == host, Event.id != exclude_event_id)
            .where(Event.timestamp > around, Event.timestamp <= around + RELATED_EVENTS_WINDOW)
            .order_by(Event.timestamp.asc(), Event.id.asc())
            .limit(RELATED_EVENTS_LIMIT)
        )
    )

    def _distance(event: Event) -> float:
        stamp = event.timestamp if event.timestamp.tzinfo else event.timestamp.replace(tzinfo=timezone.utc)
        anchor = around if around.tzinfo else around.replace(tzinfo=timezone.utc)
        return abs((stamp - anchor).total_seconds())

    nearest = sorted(before + after, key=lambda e: (_distance(e), e.id))[:RELATED_EVENTS_LIMIT]
    return sorted(nearest, key=lambda e: (e.timestamp, e.id))


# The evidence used to carry only process, parent, command line and user. The
# 19 Oct 2026 RAG audit showed what that costs: for a network connection, a file
# write or a registry change the explanation said the destination, file name or
# registry value "is not in the evidence" (4 of 10 spot-check incidents), guessed
# a Run key "probably points to %APPDATA%" when it pointed to C:\Users\Public,
# and chat could not name the service or the C2 address of a real PsExec capture.
# The event's own fields are now passed, minus identifiers that carry no meaning
# for an analyst, and bounded so the prompt stays within the provider's limits.
_DETAIL_FIELDS_SKIPPED = frozenset({
    "Image", "CommandLine", "User", "ParentImage",  # already promoted above
    "ProcessGuid", "ParentProcessGuid", "SourceProcessGUID", "TargetProcessGUID", "LogonGuid",
    "SourceProcessGuid", "TargetProcessGuid", "UtcTime", "RuleName", "SubjectUserSid",
    "SubjectLogonId", "TargetLogonId", "LogonId", "TerminalSessionId", "SourceThreadId",
    "SourceProcessId", "TargetProcessId", "ProcessId", "ParentProcessId", "ThreadID",
    "KeyLength", "TransmittedServices", "LmPackageName", "Version", "Opcode", "Task", "Keywords",
})
_MAX_DETAIL_FIELDS = 15
_MAX_DETAIL_CHARS = 240
# Fields worth a mention on a related-event line, in order of preference.
_RELATED_KEY_FIELDS = (
    "DestinationIp", "DestinationPort", "TargetFilename", "TargetObject", "Details", "PipeName",
    "ServiceName", "ImagePath", "ServiceFileName", "TargetUserName", "MemberName", "ShareName",
    "RelativeTargetName", "TaskName", "QueryName", "TargetImage", "GrantedAccess", "ImageLoaded",
    "IpAddress", "LogonType",
)
_RELATED_LINE_CHARS = 400


def _event_data(event: Event) -> dict:
    data = ((event.raw_json or {}).get("normalized") or {}).get("event_data") or {}
    return data if isinstance(data, dict) else {}


def _clip(value: object, limit: int) -> str:
    text = " ".join(str(value).split())
    return text if len(text) <= limit else f"{text[:limit]}... [{len(text) - limit} more chars]"


def _event_details(event: Event) -> list[str]:
    """The detection event's own fields as "Name: value" lines, bounded."""
    lines = []
    for name, value in _event_data(event).items():
        if name in _DETAIL_FIELDS_SKIPPED or value in (None, "", "-", [], {}):
            continue
        lines.append(f"{name}: {_clip(value, _MAX_DETAIL_CHARS)}")
        if len(lines) == _MAX_DETAIL_FIELDS:
            break
    return lines


def _related_event_line(event: Event) -> str:
    data = _event_data(event)
    keys = ", ".join(
        f"{name}={_clip(data[name], 120)}" for name in _RELATED_KEY_FIELDS if data.get(name) not in (None, "", "-")
    )
    line = (
        f"{event.timestamp.isoformat()} {event.channel or 'unknown channel'} event_id={event.event_id} "
        f"process={event.process or 'unknown'} command_line={event.command_line or 'none'}"
        + (f" | {keys}" if keys else "")
    )
    return _clip(line, _RELATED_LINE_CHARS)


def build_incident_evidence(db: Session, incident: Incident) -> dict:
    """The bounded evidence package rag/explain_service.py's and
    rag/chat_service.py's LLM prompts are built from (pending.md item 5:
    "extend the evidence input beyond {title, severity, host,
    technique_id}"). Reuses get_incident_alerts_with_events/
    get_related_events above -- the exact same lookups `GET
    /incidents/{id}` already runs to build its own per-alert evidence
    list -- rather than a new query shape, so this is wiring the LLM
    prompt to data that already exists, not a new lookup.

    Bounded to the incident's FIRST alert (earliest matched_at), not
    every alert it has: some incidents carry dozens of near-duplicate
    alerts from the same rule (e.g. "Remote Thread Creation" firing once
    per CreateRemoteThread event in a file) -- dumping all of them into
    the prompt would balloon its size without adding real signal, so any
    additional alerts are only counted, not individually detailed.
    """
    evidence: dict = {
        "description": incident.title,
        "severity": incident.severity,
        "host": incident.host,
        "technique_id": incident.mitre_technique_ids[0] if incident.mitre_technique_ids else None,
        "technique_ids": incident.mitre_technique_ids or [],
    }
    # Each id with its official name from the bundled ATT&CK v19.2 dataset.
    # Found 19 Oct 2026: given the bare id T1685.005 (log clearing, an id
    # newer than the model), the explanation called it "Remote SAM Dump".
    names = load_mitre_techniques()
    evidence["techniques"] = [
        f"{tid} {names[tid]['name']}" if tid in names else tid for tid in incident.mitre_technique_ids or []
    ]

    alerts_with_events = get_incident_alerts_with_events(db, incident.id)
    if not alerts_with_events:
        return evidence

    # The primary alert is the detection the incident is titled after (see
    # find_or_create_incident's title rule), falling back to the earliest RULE
    # detection. Found 19 Oct 2026: always taking the earliest made a "Remote
    # SAM Dump" incident's explanation describe the log clear that preceded it
    # and report the dumped hive files as "not in the evidence". An ML anomaly
    # is stamped at its window start, so it can sort first -- it must never be
    # what the explanation is built around while a real detection exists.
    detections = [(a, e) for a, e in alerts_with_events if a.rule_id != ML_RULE_ID]
    titling_rule = _rule_behind_title(incident.title)
    titled = [(a, e) for a, e in detections if titling_rule is not None and a.rule_id == titling_rule.rule_id]
    primary_alert, primary_event = (titled or detections or alerts_with_events)[0]
    # Merges in the detectors that have no YAML file behind them the same way
    # get_incident_detail's own rules_by_id does -- a sequence's rule_id
    # (detection/sequences.py) and the ML layer's (app/ml/rule.py) were never
    # loaded YAML rules, so they would otherwise resolve to no title at all.
    rules_by_id = {rule.rule_id: rule for rule in get_loaded_rules()} | NON_YAML_RULES
    rule = rules_by_id.get(primary_alert.rule_id)

    evidence["matched_rule"] = rule.title if rule else None
    if primary_alert.rule_id in SEQUENCE_PATTERNS:
        evidence["detection_method"] = "multi-event sequence correlation"
    elif primary_alert.rule_id == ML_RULE_ID:
        # Naming this honestly matters downstream: the RAG explanation layer
        # reads detection_method, and an anomaly score is not a rule match.
        evidence["detection_method"] = "unsupervised behavioural anomaly (no specific technique)"
    else:
        evidence["detection_method"] = "single-event Sigma rule"
    evidence["process"] = primary_event.process
    evidence["parent_process"] = primary_event.parent_process
    evidence["command_line"] = primary_event.command_line
    evidence["user"] = primary_event.user
    # The detection's own time and source: without them the model only saw
    # related-event timestamps and was observed inventing a different year.
    evidence["event_time_utc"] = primary_event.timestamp.isoformat()
    evidence["event_source"] = f"{primary_event.channel or 'unknown channel'} event {primary_event.event_id}"

    details = _event_details(primary_event)
    if details:
        evidence["event_details"] = details

    related = get_related_events(
        db, host=primary_event.host, around=primary_event.timestamp, exclude_event_id=primary_event.id
    )
    if related:
        evidence["related_events"] = [_related_event_line(event) for event in related]

    if len(detections) > 1:
        evidence["additional_alerts"] = (
            f"{len(detections) - 1} more rule alert(s) matched on this incident, not individually listed here"
        )
    anomalies = [a for a, _e in alerts_with_events if a.rule_id == ML_RULE_ID]
    if anomalies and detections:
        evidence["supporting_anomalies"] = (
            f"{len(anomalies)} statistical anomaly flag(s) from the ML layer overlap this incident "
            "(supporting context only, not a detection)"
        )

    return evidence
