"""Shared normalize -> persist -> detect -> group -> persist-alerts pipeline.

Extracted from `api/routes_ingest.py`'s inline body so the live-replay
service (`services/replay_service.py`) runs the exact same code the
`POST /ingest` upload has always run, rather than a second copy of it that
could quietly drift out of sync. `routes_ingest.py` still does its own
file-format checks and EVTX parsing (those stay route-specific -- a replay
tick never has an uploaded file to validate); this module starts at "here
are some raw Sysmon/Windows Event dicts" and ends at the same
`IngestResponse`-shaped counts either caller returns.

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

    `matched_at`: an explicit datetime reproduces `POST /ingest`'s original,
    upload-time-stamped behavior -- every match in the batch shares one
    `Alert.matched_at`/`Incident.created_at`, byte-for-byte what every
    existing ingest test already asserts. `None` (the live-replay path)
    takes each match's own timestamp from its event instead, so an
    incident's `created_at` reflects when the activity actually happened,
    not when the batch was posted -- which is what lets replayed telemetry
    form incidents at realistic times instead of one giant incident stamped
    "now".

    When `matched_at` is `None`, `records` MUST already be in ascending
    event-timestamp order: `find_or_create_incident`'s grouping window is
    anchored on `Incident.created_at`, so an out-of-order earlier match
    could attach to a *later* incident than the one it actually belongs to.
    This is checked and raises `ValueError` rather than silently
    mis-grouping -- the replay driver is the only caller that hits this
    path, and it always emits chronologically, so tripping it means a real
    bug in the caller, not a data quirk to route around.
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
