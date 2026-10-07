"""Cut normalized events into (host, family, 10-minute bucket) windows --
the single definition shared by training, evaluation and live ingest so the
three can never disagree about what a window is."""

from collections import defaultdict
from datetime import datetime

from app.ml.features import family_of, window_start
from app.schemas.event import NormalizedEvent

WindowKey = tuple[str, str, datetime]


def build_windows(events, *, payload=None) -> dict[WindowKey, list]:
    """Group `events` (NormalizedEvent) into windows. With `payload`, each
    window holds payload(event) instead of the event (ingest keeps the
    persisted Event row alongside)."""
    windows: dict[WindowKey, list] = defaultdict(list)
    for event in events:
        family = family_of(event)
        if family is None:
            continue
        windows[(event.host, family, window_start(event.timestamp))].append(
            payload(event) if payload else event
        )
    return dict(windows)


def dedupe(events: list[NormalizedEvent]) -> list[NormalizedEvent]:
    """Drop repeats of the same (host, channel, EventRecordID) -- the benign
    corpus ships overlapping exports of the same logs."""
    seen: set[tuple] = set()
    unique: list[NormalizedEvent] = []
    for event in events:
        if event.event_record_id is not None:
            key = (event.host, event.channel, event.event_record_id)
            if key in seen:
                continue
            seen.add(key)
        unique.append(event)
    return unique
