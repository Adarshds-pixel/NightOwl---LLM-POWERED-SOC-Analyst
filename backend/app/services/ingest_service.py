"""Shared normalize -> persist -> detect -> group -> persist-alerts pipeline.

Extracted from `api/routes_ingest.py`'s inline body so the pipeline itself is
testable independent of the HTTP/EVTX-parsing concerns `routes_ingest.py`
still owns (file-format checks, multipart handling); this module starts at
"here are some raw Sysmon/Windows Event dicts" and ends at the
`IngestResponse`-shaped counts the route returns.

`rules` is a parameter rather than a `get_loaded_rules()` call inside this
function, on purpose: several existing tests
(`tests/api/test_ingest_{alerts,detection,incidents}.py`) monkeypatch
`app.api.routes_ingest.get_loaded_rules` to inject a fake rule. Keeping the
call at that module's scope, with the loaded list threaded through here,
means those tests still patch the thing that actually runs.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

from sqlalchemy.orm import Session

from app.detection.engine import evaluate_event
from app.detection.rule_loader import LoadedRule
from app.ingestion.normalizer import EventNormalizationError, normalize_event
from app.services.detection_service import save_alerts
from app.services.event_service import save_events
from app.services.incident_service import find_or_create_incident

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IngestOutcome:
    records_read: int
    events_ingested: int
    events_skipped: int
    rule_matches: int
    matched_rule_titles: list[str] = field(default_factory=list)
    alerts_created: int = 0
    incident_ids: list[int] = field(default_factory=list)


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

    saved = save_events(db, normalized_events)

    matched_titles: list[str] = []
    rule_matches = 0
    alert_data = []
    incident_ids: list[int] = []

    for event_row, normalized_event in zip(saved, normalized_events, strict=True):
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

    alerts = save_alerts(db, alert_data)

    return IngestOutcome(
        records_read=records_read,
        events_ingested=len(saved),
        events_skipped=skipped,
        rule_matches=rule_matches,
        matched_rule_titles=matched_titles,
        alerts_created=len(alerts),
        incident_ids=incident_ids,
    )
