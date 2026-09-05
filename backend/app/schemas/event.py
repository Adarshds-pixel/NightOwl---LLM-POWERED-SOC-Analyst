"""Common event schema (Vol1 §3.2) that every Sysmon event normalizes into.

Universal fields (host, timestamp, event_id, process, command_line, user)
are populated for every event. Type-specific fields are populated only for
the event IDs normalizer.py currently maps (1, 3, 11); everything else is
None for other event IDs -- see normalizer.py's dispatch table, not this
file, for which event IDs currently populate what.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class NormalizedEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    # Universal -- mirrors models/event.py's flat columns
    host: str
    timestamp: datetime
    event_id: int
    process: str | None = None
    # Promoted alongside `process` (pending.md "ParentImage promotion") --
    # only ever populated for process-creation events, same as `process`
    # itself. See models/event.py's own field comment for the source
    # fields (Sysmon ParentImage / Security-aliased ParentProcessName).
    parent_process: str | None = None
    command_line: str | None = None
    user: str | None = None

    # Raw `Event.System.Channel` (e.g. "Microsoft-Windows-Sysmon/Operational",
    # "Security"), unmodified. Event IDs are not unique across channels --
    # see normalizer.py's `canonical_channel()` for the classifier that
    # reduces this to a small set of known tokens for scoping/coverage
    # purposes; this field itself stays raw so nothing about the source is
    # lost for display/debugging.
    channel: str | None = None

    # Raw `Event.System.EventRecordID` -- Windows' own per-(host, channel)
    # monotonic record identity, not something NightOwl invents. Used only
    # for ingest-time duplicate detection (see event_service.py); None
    # when a record genuinely lacks it (malformed/legacy), in which case
    # that event is never deduplicated rather than guessed at.
    event_record_id: int | None = None

    # Event ID 3 -- network connection
    protocol: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None

    # Event ID 11 -- file create
    target_filename: str | None = None

    # Flattened Sysmon EventData (Image, CommandLine, DestinationIp, ...),
    # every field the record carries -- not just the ones above that get
    # promoted to their own column. Lets detection/engine.py match rules
    # written against real Sysmon field names (portable from public Sigma
    # rules) without re-parsing the raw XML itself; normalizer.py has
    # already computed this dict for its own type_fields extraction, so
    # this just exposes that existing computation instead of duplicating it.
    event_data: dict[str, str | None] = Field(default_factory=dict, repr=False)

    # Full original xmltodict-parsed record, for provenance/audit trail.
    # Excluded from model_dump() by default so reuse of this schema
    # elsewhere (API responses, logs) never leaks the raw blob
    # unintentionally -- event_service.py reaches `.raw` directly when
    # building the persisted raw_json.
    raw: dict = Field(exclude=True, repr=False)
