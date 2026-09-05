"""Shared normalize -> persist -> detect -> group -> persist-alerts pipeline.

Extracted from `api/routes_ingest.py`'s inline body so the pipeline itself is
testable independent of the HTTP/EVTX-parsing concerns `routes_ingest.py`
still owns (file-format checks, multipart handling); this module starts at
"here are some raw Sysmon/Windows Event dicts" and ends at the
`IngestResponse`-shaped counts the route returns -- including the telemetry-
profiler fields (`channels`, `providers`, `event_id_breakdown`) that show
what's actually in a file, computed in the same pass as everything else
rather than a second read of the upload, and the 2-pattern sequence engine
(`detection/sequences.py`) that runs once over the whole persisted batch
after the per-event rule loop below, for the handful of techniques a
single-event rule structurally cannot express.

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
from datetime import datetime
from typing import Iterable

from sqlalchemy.orm import Session

from app.detection.engine import covered_event_ids, evaluate_event
from app.detection.rule_loader import LoadedRule
from app.detection.sequences import detect_sequences
from app.ingestion.normalizer import EventNormalizationError, canonical_channel, normalize_event
from app.services.advisory_patterns import is_named_pipe_discovery
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
    covered_events: int = 0
    uncovered_events: int = 0
    uncovered_breakdown: list[UncoveredEventGroup] = field(default_factory=list)
    uncovered_event_ids: list[int] = field(default_factory=list)
    # Event ids matching a narrow, verified advisory pattern (see
    # advisory_patterns.py) -- independent of coverage/rule_matches, since
    # the pattern can occur in an otherwise fully-covered or already-alerted
    # file and still deserve a second look (routes_ingest.py folds these
    # into the same AI-opinion mechanism used for uncovered events).
    named_pipe_discovery_event_ids: list[int] = field(default_factory=list)
    # Telemetry profiler (pending.md item 4): what's actually in this file,
    # computed from the same normalize pass rather than a second read of
    # the upload -- distinct raw Channel/Provider strings seen, and the
    # full per-(channel, event_id) breakdown with each group's coverage
    # verdict (a superset of uncovered_breakdown above).
    channels: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    event_id_breakdown: list[EventIdCoverageGroup] = field(default_factory=list)


def ingest_records(
    db: Session,
    records: Iterable[dict],
    *,
    rules: list[LoadedRule],
    matched_at: datetime | None = None,
) -> IngestOutcome:
    """Normalizes `records`, persists them as events, evaluates each against
    `rules`, and groups/persists any matches as alerts.

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
    alert_data = []
    incident_ids: list[int] = []
    covered_pairs = covered_event_ids(rules)
    covered_count = 0
    # Counter key uses the raw channel string (not the canonical token) so
    # the breakdown stays human-readable -- e.g. two different unrecognized
    # channels both canonicalize to None but should still list separately.
    uncovered_counter: Counter[tuple[str | None, int]] = Counter()
    uncovered_event_ids: list[int] = []
    named_pipe_discovery_event_ids: list[int] = []
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

        if pair in covered_pairs:
            covered_count += 1
        else:
            uncovered_counter[(normalized_event.channel, normalized_event.event_id)] += 1
            if len(uncovered_event_ids) < MAX_UNCOVERED_SAMPLE:
                uncovered_event_ids.append(event_row.id)

        if len(named_pipe_discovery_event_ids) < MAX_ADVISORY_SAMPLE and is_named_pipe_discovery(
            normalized_event.channel, normalized_event.event_id, normalized_event.event_data
        ):
            named_pipe_discovery_event_ids.append(event_row.id)

        matches = evaluate_event(normalized_event, rules)
        if not matches:
            continue
        stamp = matched_at if matched_at is not None else normalized_event.timestamp
        for match in matches:
            rule_matches += 1
            if match.title not in matched_titles:
                matched_titles.append(match.title)
            incident = find_or_create_incident(db, normalized_event.host, stamp, match)
            if incident.id not in incident_ids:
                incident_ids.append(incident.id)
            alert_data.append((event_row.id, match, stamp, incident.id))

    # The 2-pattern sequence engine (pending.md item 5): needs the whole
    # batch at once (a multi-event correlation, not a per-event rule), so
    # it runs after the per-event loop above rather than inside it. Feeds
    # the exact same incident/alert plumbing every regular rule match
    # already uses -- see detection/sequences.py's module docstring for
    # why this is a hand-written pair of detectors, not a new subsystem.
    for anchor_event, match in detect_sequences(list(zip(saved, normalized_events, strict=True))):
        rule_matches += 1
        if match.title not in matched_titles:
            matched_titles.append(match.title)
        stamp = matched_at if matched_at is not None else anchor_event.timestamp
        incident = find_or_create_incident(db, anchor_event.host, stamp, match)
        if incident.id not in incident_ids:
            incident_ids.append(incident.id)
        alert_data.append((anchor_event.id, match, stamp, incident.id))

    alerts = save_alerts(db, alert_data)

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
    alerted_event_ids = {event_id for event_id, _match, _stamp, _incident_id in alert_data}
    named_pipe_discovery_event_ids = [
        event_id for event_id in named_pipe_discovery_event_ids if event_id not in alerted_event_ids
    ]

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
        uncovered_events=sum(uncovered_counter.values()),
        uncovered_breakdown=uncovered_breakdown,
        uncovered_event_ids=uncovered_event_ids,
        named_pipe_discovery_event_ids=named_pipe_discovery_event_ids,
        channels=sorted(channels_seen),
        providers=sorted(providers_seen),
        event_id_breakdown=event_id_breakdown,
    )
