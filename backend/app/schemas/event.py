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
    command_line: str | None = None
    user: str | None = None

    # Event ID 3 -- network connection
    protocol: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None

    # Event ID 11 -- file create
    target_filename: str | None = None

    # Full original xmltodict-parsed record, for provenance/audit trail.
    # Excluded from model_dump() by default so reuse of this schema
    # elsewhere (API responses, logs) never leaks the raw blob
    # unintentionally -- event_service.py reaches `.raw` directly when
    # building the persisted raw_json.
    raw: dict = Field(exclude=True, repr=False)
