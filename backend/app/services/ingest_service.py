"""Shared normalize -> persist -> detect -> group -> persist-alerts pipeline.

Extracted from `api/routes_ingest.py`'s inline body so the pipeline itself is
testable independent of the HTTP/EVTX-parsing concerns `routes_ingest.py`
still owns (file-format checks, multipart handling); this module starts at
"here are some raw Sysmon/Windows Event dicts" and ends at the
`IngestResponse`-shaped counts the route returns -- including the telemetry-
profiler fields (`channels`, `providers`, `event_id_breakdown`) that show
what's actually in a file, computed in the same pass as everything else
rather than a second read of the upload, the multi-event sequence engine
(`detection/sequences.py`) that runs once over the whole persisted batch
after the per-event rule loop below, for the handful of techniques a
single-event rule structurally cannot express, and the ML anomaly layer
(`app/ml/`) that scores each 10-minute host window in the batch.

`rules` is a parameter rather than a `get_loaded_rules()` call inside this
function, on purpose: several existing tests
(`tests/api/test_ingest_{alerts,detection,incidents}.py`) monkeypatch
`app.api.routes_ingest.get_loaded_rules` to inject a fake rule. Keeping the
call at that module's scope, with the loaded list threaded through here,
means those tests still patch the thing that actually runs.
"""

import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.detection.coverage import CHECKED, ROUTINE, checked_pairs, classify
from app.detection.engine import RuleMatch, evaluate_event
from app.detection.rule_loader import LoadedRule
from app.detection.sequences import NAMED_PIPE_SWEEP, SMB_SHARE_ENUM_PROBE, detect_sequences
from app.core.config import settings
from app.ml.features import WINDOW
from app.ml.rule import ML_ANOMALY_RULE, ML_RULE_ID
from app.ml.runtime import get_detector
from app.ml.windows import build_windows
from app.ingestion.normalizer import EventNormalizationError, canonical_channel, normalize_event
from app.services.advisory_patterns import is_named_pipe_discovery, is_non_kernel_driver_service_installation
from app.services import severity_service
from app.services.detection_service import save_alerts
from app.services.event_service import find_existing_event_keys, save_events
from app.services.incident_service import find_or_create_incident

logger = logging.getLogger(__name__)

# Cap on how many uncovered Event ids are carried in IngestOutcome for a
# downstream consumer (e.g. an LLM second-opinion pass) to sample from --
# bounds memory/payload size on a very large file without needing the full
# list; the counts/breakdown below stay exact regardless of this cap.
MAX_UNCOVERED_SAMPLE = 25

# Same idea as MAX_UNCOVERED_SAMPLE, for advisory-pattern-flagged event ids
# (see advisory_patterns.py) -- these are always few in practice (a handful
# of named-pipe connects per file), so this is a safety bound, not a limit
# expected to bind on real data.
MAX_ADVISORY_SAMPLE = 10

# Identical repeat matches -- same rule, host, acting process and target --
# within this window of the previous one fold into one alert with an
# occurrence count. One capture used to produce 83 identical "Remote Thread
# Creation" alerts, which buries everything else in the queue.
ALERT_DEDUP_WINDOW = timedelta(seconds=60)


# Sequence detectors whose evidence is a burst of named-pipe connections (see
# the advisory filtering in ingest_records).
_PIPE_SEQUENCE_RULE_IDS = frozenset({NAMED_PIPE_SWEEP.rule_id, SMB_SHARE_ENUM_PROBE.rule_id})


def _alert_dedup_key(rule_id: str, event) -> tuple:
    data = event.event_data or {}
    actor = event.process or data.get("SourceImage") or data.get("Image")
    target = (
        data.get("TargetImage")
        or data.get("TargetFilename")
        or data.get("TargetObject")
        or data.get("TargetUserName")
        or event.command_line
    )
    return (rule_id, event.host, (actor or "").lower(), (target or "").lower())


def _lock_hosts(db: Session, hosts: set[str]) -> None:
    """Serialise concurrent ingests that touch the same host (Postgres only).

    Without this, two uploads of the same file running at once both pass the
    duplicate-event check before either commits, storing every event twice,
    and both can create a new incident for the same host and hour. The lock
    is transaction-scoped: released by the caller's commit/rollback. Taken in
    sorted order so two multi-host uploads cannot deadlock.
    """
    bind = db.get_bind()
    if bind is None or bind.dialect.name != "postgresql":
        return
    for host in sorted(hosts):
        db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:host))"), {"host": host})


@dataclass(frozen=True)
class IngestNotice:
    """Something worth knowing about a file that is not a detection (e.g. an
    event log was cleared by a named account). Never opens an alert/incident
    and never changes the verdict."""

    kind: str
    message: str
    count: int


@dataclass(frozen=True)
class UncoveredEventGroup:
    channel: str | None
    event_id: int
    count: int


@dataclass(frozen=True)
class EventIdCoverageGroup:
    """Like UncoveredEventGroup, but for every (channel, event_id) group in
    the file -- covered ones included -- plus the coverage verdict itself,
    so a consumer (the telemetry-profiler panel) can show "what's actually
    in this file and what's detectable" without a second pass over the
    data. UncoveredEventGroup/uncovered_breakdown stay as they were: this
    is an additive, superset view, not a replacement.
    """

    channel: str | None
    event_id: int
    count: int
    covered: bool
    # "checked" | "routine" | "unchecked" -- see detection/coverage.py.
    # `covered` stays (checked only) for older readers.
    kind: str = "unchecked"


@dataclass(frozen=True)
class IngestOutcome:
    records_read: int
    events_ingested: int
    events_skipped: int
    # Records that parsed and normalized fine but were recognized as an
    # event NightOwl already has stored (same host/channel/EventRecordID --
    # see event_service.find_existing_event_keys) and so were never
    # inserted. Distinct from events_skipped (a normalization failure):
    # this is "already ingested," not "malformed." Never counted in
    # events_ingested, records_read still counts the raw record either way.
    duplicate_events_skipped: int
    rule_matches: int
    matched_rule_titles: list[str] = field(default_factory=list)
    alerts_created: int = 0
    incident_ids: list[int] = field(default_factory=list)
    # covered_events = CHECKED (a rule or sequence detector evaluates it);
    # routine_events = everyday activity that needs no rule; uncovered_events
    # = UNCHECKED only (security-relevant or unknown, nothing evaluates it).
    covered_events: int = 0
    routine_events: int = 0
    uncovered_events: int = 0
    uncovered_breakdown: list[UncoveredEventGroup] = field(default_factory=list)
    uncovered_event_ids: list[int] = field(default_factory=list)
    notices: list[IngestNotice] = field(default_factory=list)
    # Event ids matching a narrow, verified advisory pattern (see
    # advisory_patterns.py) -- independent of coverage/rule_matches, since
    # the pattern can occur in an otherwise fully-covered or already-alerted
    # file and still deserve a second look (routes_ingest.py folds these
    # into the same AI-opinion mechanism used for uncovered events).
    named_pipe_discovery_event_ids: list[int] = field(default_factory=list)
    # Same idea, second independent pattern (see
    # advisory_patterns.is_non_kernel_driver_service_installation):
    # Security Event ID 4697 whose ServiceType the one loaded 4697 rule
    # doesn't evaluate -- "covered by a rule's logsource" is not the same
    # claim as "this event's content was actually judged," and this list
    # exists so the AI safety net still engages on the remainder instead of
    # reading a covered-but-unmatched malicious service install as clean.
    service_installation_event_ids: list[int] = field(default_factory=list)
    # Telemetry profiler (pending.md item 4): what's actually in this file,
    # computed from the same normalize pass rather than a second read of
    # the upload -- distinct raw Channel/Provider strings seen, and the
    # full per-(channel, event_id) breakdown with each group's coverage
    # verdict (a superset of uncovered_breakdown above).
    channels: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    event_id_breakdown: list[EventIdCoverageGroup] = field(default_factory=list)
    # ML anomaly layer (app/ml/), kept apart from rule detections on purpose:
    # an anomaly score is not a rule match, so it never counts toward
    # rule_matches / matched_rule_titles (which the AI-opinion prompt reads as
    # "already detected by a rule") -- it has its own count and titles.
    ml_anomalies: int = 0
    ml_anomaly_titles: list[str] = field(default_factory=list)


def ingest_records(
    db: Session,
    records: Iterable[dict],
    *,
    rules: list[LoadedRule],
    matched_at: datetime | None = None,
) -> IngestOutcome:
    """Normalizes `records`, stages them as events, evaluates each against
    `rules`, and groups/stages any matches as alerts and incidents.

    Caller must commit. This function only `flush()`es (via `save_events`/
    `save_alerts`/`find_or_create_incident`) -- it never calls `db.commit()`
    itself, so nothing here is durable until the caller does. This is
    deliberate: it lets `routes_ingest.py` extend one atomic transaction
    across this call *and* whatever it does afterward (e.g. persisting an
    AI-opinion row) with a single `db.commit()` of its own, rather than
    ending the transaction here and forcing a second, separate one. A
    caller that never commits will see its own flushed rows within the same
    session (flush is enough for same-session visibility) but nothing will
    survive past that session closing -- see
    `tests/services/test_ingestion_transaction.py` for both cases exercised
    directly, and `routes_ingest.py`'s own `db.commit()` for the real,
    production call site.

    `matched_at=None` (the default, and what `POST /ingest` always passes)
    takes each match's own timestamp from its event, so an incident's
    `created_at` reflects when the activity actually happened rather than
    when it was uploaded -- this is what makes `find_or_create_incident`'s
    same-host-within-an-hour grouping mean something real: two unrelated
    EVTX files uploaded back-to-back only merge into one incident if the
    activity they recorded genuinely happened close together, not merely
    because they were uploaded close together.

    An explicit `matched_at` stamps every match in the batch with one shared
    timestamp instead -- useful for tests that want a deterministic
    `Alert.matched_at`/`Incident.created_at` without needing to reason about
    a fixture's real event times.

    When `matched_at` is `None`, `records` MUST already be in ascending
    event-timestamp order: `find_or_create_incident`'s grouping window is
    anchored on `Incident.created_at`, so an out-of-order earlier match
    could attach to a *later* incident than the one it actually belongs to.
    This is checked and raises `ValueError` rather than silently
    mis-grouping -- `routes_ingest.py` sorts records by timestamp before
    calling this, so tripping it means a real bug in that sort, not a data
    quirk to route around.
    """
    records_read = 0
    skipped = 0
    normalized_events = []
    previous_timestamp: datetime | None = None

    for record in records:
        records_read += 1
        try:
            normalized = normalize_event(record)
        except EventNormalizationError as e:
            logger.warning("skipping malformed record: %s", e)
            skipped += 1
            continue

        if matched_at is None:
            if previous_timestamp is not None and normalized.timestamp < previous_timestamp:
                raise ValueError(
                    "ingest_records(matched_at=None) requires ascending event timestamps -- "
                    f"got {normalized.timestamp.isoformat()} after {previous_timestamp.isoformat()}"
                )
            previous_timestamp = normalized.timestamp

        normalized_events.append(normalized)

    _lock_hosts(db, {e.host for e in normalized_events})

    # Duplicate detection (the same EVTX file, or a re-export overlapping
    # an earlier one, uploaded twice): skip re-inserting any event whose
    # (host, channel, event_record_id) already exists, so a repeat upload
    # never doubles every event/alert/incident-derived KPI -- see
    # event_service.find_existing_event_keys(). Events without an
    # event_record_id (rare/malformed) are never deduplicated: silently
    # dropping something NightOwl can't prove is a duplicate would be
    # worse than occasionally re-storing one.
    keys_with_ids = {
        (e.host, e.channel, e.event_record_id) for e in normalized_events if e.event_record_id is not None
    }
    existing_keys = find_existing_event_keys(db, keys_with_ids)
    deduplicated_events = []
    duplicate_count = 0
    seen_in_batch: set[tuple[str, str | None, int]] = set()
    for normalized in normalized_events:
        if normalized.event_record_id is not None:
            key = (normalized.host, normalized.channel, normalized.event_record_id)
            if key in existing_keys or key in seen_in_batch:
                duplicate_count += 1
                continue
            seen_in_batch.add(key)
        deduplicated_events.append(normalized)
    normalized_events = deduplicated_events

    saved = save_events(db, normalized_events)

    matched_titles: list[str] = []
    rule_matches = 0
    alert_data: list[tuple] = []
    # dedup key -> (index into alert_data, timestamp of the latest fold-in)
    open_alerts: dict[tuple, tuple[int, datetime]] = {}
    incident_ids: list[int] = []
    covered_pairs = checked_pairs(rules)
    covered_count = 0
    routine_count = 0
    log_notice_counter: Counter[tuple[str, str]] = Counter()
    # Counter key uses the raw channel string (not the canonical token) so
    # the breakdown stays human-readable -- e.g. two different unrecognized
    # channels both canonicalize to None but should still list separately.
    uncovered_counter: Counter[tuple[str | None, int]] = Counter()
    uncovered_event_ids: list[int] = []
    named_pipe_discovery_event_ids: list[int] = []
    service_installation_event_ids: list[int] = []
    # Telemetry profiler: every (channel, event_id) group, covered or not
    # (a superset of uncovered_counter above), plus the distinct raw
    # channel/provider strings actually present in the file.
    event_counter: Counter[tuple[str | None, int]] = Counter()
    channels_seen: set[str] = set()
    providers_seen: set[str] = set()

    for event_row, normalized_event in zip(saved, normalized_events, strict=True):
        pair = (canonical_channel(normalized_event.channel), normalized_event.event_id)
        event_counter[(normalized_event.channel, normalized_event.event_id)] += 1
        if normalized_event.channel:
            channels_seen.add(normalized_event.channel)
        provider = normalized_event.raw.get("Event", {}).get("System", {}).get("Provider")
        if isinstance(provider, dict):
            provider_name = provider.get("@Name")
            if isinstance(provider_name, str) and provider_name:
                providers_seen.add(provider_name)

        if pair == ("system", 104):
            data = normalized_event.event_data or {}
            who = normalized_event.user or data.get("SubjectUserName") or "an unknown account"
            log_notice_counter[(who, data.get("Channel") or "an event log")] += 1
        kind = classify(pair[0], pair[1], covered_pairs)
        if kind == CHECKED:
            covered_count += 1
        elif kind == ROUTINE:
            routine_count += 1
        else:
            uncovered_counter[(normalized_event.channel, normalized_event.event_id)] += 1
            # uncovered_event_ids itself is built in a second, cheap pass
            # below (over these same already-in-memory lists, no re-read/
            # re-evaluation) once uncovered_counter's final group count is
            # known -- see the round-robin selection after this loop.

        if len(named_pipe_discovery_event_ids) < MAX_ADVISORY_SAMPLE and is_named_pipe_discovery(
            normalized_event.channel, normalized_event.event_id, normalized_event.event_data
        ):
            named_pipe_discovery_event_ids.append(event_row.id)

        if len(service_installation_event_ids) < MAX_ADVISORY_SAMPLE and is_non_kernel_driver_service_installation(
            normalized_event.channel, normalized_event.event_id, normalized_event.event_data
        ):
            service_installation_event_ids.append(event_row.id)

        matches = evaluate_event(normalized_event, rules)
        if not matches:
            continue
        stamp = matched_at if matched_at is not None else normalized_event.timestamp
        for match in matches:
            rule_matches += 1
            if match.title not in matched_titles:
                matched_titles.append(match.title)
            key = _alert_dedup_key(match.rule_id, normalized_event)
            previous = open_alerts.get(key)
            if previous is not None and normalized_event.timestamp - previous[1] <= ALERT_DEDUP_WINDOW:
                index, _ = previous
                event_id_, match_, stamp_, incident_id_, extras = alert_data[index]
                extras["occurrence_count"] += 1
                extras["last_matched_at"] = stamp
                open_alerts[key] = (index, normalized_event.timestamp)
                continue
            # find_or_create_incident() runs one SELECT (+ a flush on
            # create) per call, i.e. once per (event, matching rule) pair --
            # no in-call cache short-circuits repeat lookups for the same
            # host. Deliberately not "fixed" by adding one: a naive
            # host-only cache would be wrong, not just slow -- a single
            # ingest call CAN legitimately produce multiple separate
            # incidents for the same host (matched_at=None, events spanning
            # more than the 1h grouping window -- see
            # test_matched_at_none_uses_each_event_own_timestamp in
            # tests/services/test_ingest_service.py, which exercises exactly
            # this). Replicating that window-overlap logic correctly
            # in-memory is real complexity for a benefit that only matters
            # at match volumes this project's real fixture corpus doesn't
            # reach today (at most a few dozen matches per file). The actual
            # fix for this pattern's cost, not its count, is the composite
            # index on Incident.host/status/created_at (models/incident.py)
            # -- each of these N queries was a full sequential scan before
            # that existed. Revisit a real in-call cache only if a future
            # profiling run shows match volume growing enough for the count
            # itself to matter, and build it against the window semantics
            # above, not host alone.
            incident = find_or_create_incident(db, normalized_event.host, stamp, match)
            if incident.id not in incident_ids:
                incident_ids.append(incident.id)
            open_alerts[key] = (len(alert_data), normalized_event.timestamp)
            alert_data.append(
                (event_row.id, match, stamp, incident.id, {"occurrence_count": 1, "last_matched_at": None})
            )

    # The multi-event sequence engine (pending.md item 5): needs the whole
    # batch at once (a multi-event correlation, not a per-event rule), so
    # it runs after the per-event loop above rather than inside it. Feeds
    # the exact same incident/alert plumbing every regular rule match
    # already uses -- see detection/sequences.py's module docstring for
    # why this is a hand-written pair of detectors, not a new subsystem.
    pipe_detector_hosts: set[str] = set()
    for anchor_event, match in detect_sequences(list(zip(saved, normalized_events, strict=True))):
        if match.rule_id in _PIPE_SEQUENCE_RULE_IDS:
            pipe_detector_hosts.add(anchor_event.host)
        rule_matches += 1
        if match.title not in matched_titles:
            matched_titles.append(match.title)
        stamp = matched_at if matched_at is not None else anchor_event.timestamp
        incident = find_or_create_incident(db, anchor_event.host, stamp, match)
        if incident.id not in incident_ids:
            incident_ids.append(incident.id)
        alert_data.append((anchor_event.id, match, stamp, incident.id))

    alerts = save_alerts(db, alert_data)

    ml_anomalies, ml_anomaly_titles = _run_ml_layer(db, saved, normalized_events, incident_ids)

    # An advisory-flagged event that also became a real alert (either a
    # per-event rule or a sequence's anchor event, e.g. the SMB-enum-probe
    # sequence sharing its PipeConnect event with is_named_pipe_discovery())
    # already has a real, confident detection explaining it -- dropping it
    # here doesn't disable the advisory pattern for *other*, unrelated
    # named-pipe events elsewhere in the file, only for this exact one.
    # Found live during the 39-file visual QA pass: without this, the same
    # ingest showed a confident "SUSPICIOUS ACTIVITY DETECTED" verdict next
    # to an AI opinion saying "insufficient information" about the identical
    # evidence.
    #
    # A sequence detector alerts on ONE anchor event but its evidence is the
    # whole burst. Found in the 10 Oct 2026 fixture audit: the named-pipe sweep
    # and share-enumeration captures showed a detection next to an AI review
    # calling the rest of the very same pipe connections "nothing unusual". So
    # when a pipe-based sequence detector fired on a host, none of that host's
    # named-pipe events go to the advisory review.
    alerted_event_ids = {item[0] for item in alert_data}
    host_of_event = {row.id: row.host for row in saved}
    named_pipe_discovery_event_ids = [
        event_id
        for event_id in named_pipe_discovery_event_ids
        if event_id not in alerted_event_ids and host_of_event.get(event_id) not in pipe_detector_hosts
    ]
    service_installation_event_ids = [
        event_id for event_id in service_installation_event_ids if event_id not in alerted_event_ids
    ]

    # Round-robin sample selection: a second, cheap pass over the same
    # already-in-memory `saved`/`normalized_events` lists (no DB I/O, no
    # rule re-evaluation), now that uncovered_counter's final distinct-group
    # count is known. First-N-chronological used to let 25 consecutive
    # events of one uncovered type exhaust the whole sample budget before a
    # second event type was ever seen (proven live against a real capture:
    # 1,531 uncovered PowerShell-lifecycle events of the same 2-3 event IDs
    # crowded out everything else).
    #
    # Capping each group's contribution alone isn't enough: a downstream
    # consumer (ai_opinion_service.MAX_SAMPLE_EVENTS) takes a much smaller
    # slice off the FRONT of uncovered_event_ids, so if this list held
    # "all of group A's slots, then all of group B's", a small front-slice
    # would still only ever see group A. The ids must be genuinely
    # interleaved -- round 0 takes one id from every group (in first-seen
    # order), round 1 takes a second id from every group that still has
    # one, and so on -- so that for ANY N, the first N ids already cover
    # up to N distinct groups before any group gets a second entry. This
    # keeps the *pool* bounded at the unchanged MAX_UNCOVERED_SAMPLE total,
    # and additionally keeps every smaller downstream slice of it diverse.
    distinct_uncovered_groups = len(uncovered_counter)
    per_group_cap = max(1, -(-MAX_UNCOVERED_SAMPLE // distinct_uncovered_groups)) if distinct_uncovered_groups else 0
    if distinct_uncovered_groups:
        uncovered_by_group: dict[tuple[str | None, int], list[int]] = {}
        for event_row, normalized_event in zip(saved, normalized_events, strict=True):
            group = (normalized_event.channel, normalized_event.event_id)
            if group not in uncovered_counter:
                continue  # covered event -- not part of this sample
            bucket = uncovered_by_group.setdefault(group, [])
            if len(bucket) < per_group_cap:
                bucket.append(event_row.id)

        group_order = list(uncovered_by_group.keys())  # insertion order == first-seen order
        round_index = 0
        while len(uncovered_event_ids) < MAX_UNCOVERED_SAMPLE:
            added_any_this_round = False
            for group in group_order:
                if len(uncovered_event_ids) >= MAX_UNCOVERED_SAMPLE:
                    break
                bucket = uncovered_by_group[group]
                if round_index < len(bucket):
                    uncovered_event_ids.append(bucket[round_index])
                    added_any_this_round = True
            if not added_any_this_round:
                break
            round_index += 1

    uncovered_breakdown = [
        UncoveredEventGroup(channel=channel, event_id=event_id, count=count)
        for (channel, event_id), count in sorted(uncovered_counter.items(), key=lambda item: -item[1])
    ]
    event_id_breakdown = [
        EventIdCoverageGroup(
            channel=channel,
            event_id=event_id,
            count=count,
            covered=(canonical_channel(channel), event_id) in covered_pairs,
            kind=classify(canonical_channel(channel), event_id, covered_pairs),
        )
        for (channel, event_id), count in sorted(event_counter.items(), key=lambda item: -item[1])
    ]

    return IngestOutcome(
        records_read=records_read,
        events_ingested=len(saved),
        events_skipped=skipped,
        duplicate_events_skipped=duplicate_count,
        rule_matches=rule_matches,
        matched_rule_titles=matched_titles,
        alerts_created=len(alerts),
        incident_ids=incident_ids,
        covered_events=covered_count,
        routine_events=routine_count,
        notices=[
            IngestNotice(
                kind="log_cleared",
                message=f"The {log} log was cleared by {who}" + (f" ({count} times)" if count > 1 else ""),
                count=count,
            )
            for (who, log), count in sorted(log_notice_counter.items(), key=lambda item: -item[1])
        ],
        uncovered_events=sum(uncovered_counter.values()),
        uncovered_breakdown=uncovered_breakdown,
        uncovered_event_ids=uncovered_event_ids,
        named_pipe_discovery_event_ids=named_pipe_discovery_event_ids,
        service_installation_event_ids=service_installation_event_ids,
        channels=sorted(channels_seen),
        providers=sorted(providers_seen),
        event_id_breakdown=event_id_breakdown,
        ml_anomalies=ml_anomalies,
        ml_anomaly_titles=ml_anomaly_titles,
    )


def _run_ml_layer(db: Session, saved, normalized_events, incident_ids: list[int]) -> tuple[int, list[str]]:
    """Score this batch's (host, log family, 10-minute) windows with the ML
    anomaly layer and persist any anomaly as an alert carrying its evidence.

    Deliberately kept apart from rule detection (see app/ml/rule.py):
      * anomalies never count toward rule_matches / alerts_created;
      * they never change an incident's title, severity or techniques;
      * in "advisory" mode (the default, see settings.ml_mode) they are only
        linked to an incident that already covers the host and time, and are
        otherwise stored on their own -- an anomaly score alone never opens an
        incident. "alert" mode may open one.
    A failure while scoring one window is logged and that window skipped; it
    never fails the upload.
    """
    mode = settings.ml_mode
    if mode == "off":
        return 0, []
    bundle = get_detector()
    if bundle is None:
        return 0, []

    windows = build_windows(
        [n for _row, n in zip(saved, normalized_events, strict=True)],
    )
    rows_by_identity = {id(n): row for row, n in zip(saved, normalized_events, strict=True)}
    ml_alert_data = []
    titles: list[str] = []
    for (host, family, start), events in windows.items():
        try:
            result = bundle.score(family, events)
            if result is None or result.severity == "low":
                continue
            anchor = _ml_anchor_event(events, result.top_features)
            level = "low" if mode == "advisory" else result.severity
            match = RuleMatch(
                rule_id=ML_RULE_ID,
                title=f"{ML_ANOMALY_RULE.title}: {family.capitalize()} activity",
                level=level,
                score=severity_service.compute_severity_score(level, []),
                technique_id=None,
            )
            incident = find_or_create_incident(
                db, host, start, match, advisory=True, create=(mode == "alert")
            )
            if incident is not None and incident.id not in incident_ids and mode == "alert":
                incident_ids.append(incident.id)
            details = {
                "kind": "ml_anomaly",
                "mode": mode,
                "family": family,
                "distance": round(result.distance, 2),
                "band": result.severity,
                "threshold_medium": round(result.threshold_medium, 2),
                "threshold_high": round(result.threshold_high, 2),
                "window_start": start.isoformat(),
                "window_end": (start + WINDOW).isoformat(),
                "window_events": result.window_events,
                "top_features": result.top_features,
                "novel_event_ids": result.novel_event_ids,
                "model_trained_at": bundle.created_at,
            }
            ml_alert_data.append(
                (rows_by_identity[id(anchor)].id, match, start, incident.id if incident else None,
                 {"details": details})
            )
            if match.title not in titles:
                titles.append(match.title)
        except Exception:  # noqa: BLE001 -- the ML layer is supplementary; it must never fail an upload
            logger.exception("ML scoring failed for %s/%s @ %s; window skipped", host, family, start)
    if ml_alert_data:
        save_alerts(db, ml_alert_data)
    return len(ml_alert_data), titles


def _ml_anchor_event(events, top_features: list[dict]):
    """The event that best represents why the window was flagged: the first
    event of the top contributing event id, else the window's first event."""
    for feature in top_features:
        name = feature.get("feature", "")
        if name.startswith("eid_") and name[4:].isdigit():
            event_id = int(name[4:])
            for event in events:
                if event.event_id == event_id:
                    return event
    return events[0]
