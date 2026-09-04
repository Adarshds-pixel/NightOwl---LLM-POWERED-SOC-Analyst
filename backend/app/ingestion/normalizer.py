"""Maps raw evtx_reader.py records into the common NormalizedEvent schema.

Every event gets its 3 universal fields (host, timestamp, event_id)
extracted regardless of event ID. Type-specific fields (process/
command_line/user for process creation, network fields, file fields) are
only populated for the event IDs this module explicitly maps: 1 (process
creation), 3 (network connection), 11 (file create) -- any other event ID
normalizes successfully with those extra fields left None, since deciding
whether to keep/drop/flag unrecognized event IDs is an ingest-time policy
decision (Day 6's `POST /ingest`), not this module's job.

EventNormalizationError is raised only when a valid Event row genuinely
can't be built (missing/malformed System block, EventID, or TimeCreated) --
never for an unrecognized-but-well-formed event ID.
"""

from collections.abc import Callable, Iterable, Iterator
from datetime import datetime, timedelta

from app.schemas.event import NormalizedEvent

# Timestomping (T1070.006) is detected by comparing a Sysmon Event ID 2's
# new CreationUtcTime against the file's PreviousCreationUtcTime -- but
# engine.py's rule matcher only supports literal string modifiers
# (contains/startswith/endswith), not cross-field comparison. So the
# comparison is done here, once, at normalize time, and exposed as a
# synthetic event_data key ("TimestompSuspected") a rule can match on
# directly. 5 minutes tolerates normal clock jitter/reordering while still
# catching real backdating, which is measured in hours/days/years.
_TIMESTOMP_THRESHOLD = timedelta(minutes=5)


class EventNormalizationError(Exception):
    pass


def _extract_host(system: dict) -> str:
    host = system.get("Computer")
    if not isinstance(host, str) or not host:
        raise EventNormalizationError("record missing 'System.Computer'")
    return host


def _extract_channel(system: dict) -> str | None:
    """Non-raising, unlike host/event_id/timestamp: channel is used for
    scoping/coverage honesty, not required to build a valid Event row, so
    its absence must never fail an otherwise-good record."""
    channel = system.get("Channel")
    return channel if isinstance(channel, str) and channel else None


# The single source of truth for "which channel is this," in scoping terms:
# canonical token -> the lowercase substring of the raw `System.Channel`
# string that identifies it. Real observed values (verified against actual
# sample files, not assumed): Sysmon -> 'Microsoft-Windows-Sysmon/Operational'
# (contains "sysmon"), Security -> 'Security' (contains "security"). Every
# call site that needs a channel-scoping decision (rule_loader.py, engine.py,
# this module's own Security-channel dispatch, event_service.py's SQL-level
# coverage filter) must derive from this one table rather than re-hardcoding
# a channel string comparison independently.
CHANNEL_TOKEN_SUBSTRINGS: dict[str, str] = {
    "sysmon": "sysmon",
    "security": "security",
}


def canonical_channel(raw_channel: str | None) -> str | None:
    if not raw_channel:
        return None
    lowered = raw_channel.lower()
    for token, substring in CHANNEL_TOKEN_SUBSTRINGS.items():
        if substring in lowered:
            return token
    return None


def _extract_event_id(system: dict) -> int:
    raw_event_id = system.get("EventID")
    if isinstance(raw_event_id, dict):
        raw_event_id = raw_event_id.get("#text")
    if raw_event_id is None:
        raise EventNormalizationError("record missing 'System.EventID'")
    try:
        return int(raw_event_id)
    except (TypeError, ValueError) as e:
        raise EventNormalizationError(f"unparseable EventID: {raw_event_id!r}") from e


def _extract_timestamp(system: dict) -> datetime:
    time_created = system.get("TimeCreated")
    if not isinstance(time_created, dict):
        raise EventNormalizationError("record missing 'System.TimeCreated'")
    raw_ts = time_created.get("@SystemTime")
    if not isinstance(raw_ts, str) or not raw_ts:
        raise EventNormalizationError("record missing 'System.TimeCreated.@SystemTime'")
    try:
        return datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
    except ValueError as e:
        raise EventNormalizationError(f"unparseable TimeCreated: {raw_ts!r}") from e


def _data_dict(event_data: dict | None) -> dict[str, str | None]:
    """Flattens Sysmon's `EventData.Data[@Name=...]` elements into a plain
    {name: value} dict, tolerating xmltodict's shape quirks: a single
    `<Data>` element parses to a dict (not a list), 2+ parse to a list, and
    an empty `<Data Name="X"/>` has no "#text" key at all (-> None). Non-
    Sysmon-shaped EventData (e.g. a raw string, as seen on plain Windows
    System-log events) has nothing to map and returns {}.
    """
    if not event_data:
        return {}
    data = event_data.get("Data")
    if data is None:
        return {}
    if isinstance(data, dict):
        items = [data]
    elif isinstance(data, list):
        items = data
    else:
        return {}

    result: dict[str, str | None] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("@Name")
        if name is None:
            continue
        result[name] = item.get("#text")
    return result


def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _normalize_process_creation(data: dict[str, str | None]) -> dict:
    return {
        "process": data.get("Image"),
        "command_line": data.get("CommandLine"),
        "user": data.get("User"),
    }


def _normalize_network_connection(data: dict[str, str | None]) -> dict:
    return {
        "process": data.get("Image"),
        "user": data.get("User"),
        "protocol": data.get("Protocol"),
        "source_ip": data.get("SourceIp"),
        "source_port": _to_int(data.get("SourcePort")),
        "destination_ip": data.get("DestinationIp"),
        "destination_port": _to_int(data.get("DestinationPort")),
    }


def _parse_sysmon_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
        return None


def _flag_timestomp(data: dict[str, str | None]) -> dict[str, str | None]:
    created = _parse_sysmon_utc(data.get("CreationUtcTime"))
    previous = _parse_sysmon_utc(data.get("PreviousCreationUtcTime"))
    backdated = created is not None and previous is not None and (previous - created) > _TIMESTOMP_THRESHOLD
    return {**data, "TimestompSuspected": "true" if backdated else "false"}


def _normalize_file_create(data: dict[str, str | None]) -> dict:
    return {
        "process": data.get("Image"),
        "user": data.get("User"),
        "target_filename": data.get("TargetFilename"),
    }


_SYSMON_EVENT_ID_DISPATCH: dict[int, Callable[[dict[str, str | None]], dict]] = {
    1: _normalize_process_creation,
    3: _normalize_network_connection,
    11: _normalize_file_create,
}

# Security-channel field names for the same concepts Sysmon calls
# Image/ParentImage/CommandLine/User -- confirmed against real captured
# Security-channel field values (`sample_logs/real_world_fixtures/`), not
# assumed from public schema docs alone. Only applied for `channel ==
# "security"` (see normalize_event()), so a Sysmon record's own `Image`
# etc. is never touched. `NewProcessName`/`ProcessCommandLine` only
# populate on 4688; the other two are common across most Security event
# IDs but only ever consulted here for the one ID this module dispatches
# on (4688) -- adding more Security event IDs to `_SECURITY_EVENT_ID_DISPATCH`
# is what would put the rest of this table to use.
_SECURITY_FIELD_ALIASES: dict[str, str] = {
    "NewProcessName": "Image",
    "ParentProcessName": "ParentImage",
    "ProcessCommandLine": "CommandLine",
    "SubjectUserName": "User",
}


def _apply_security_aliases(data: dict[str, str | None]) -> dict[str, str | None]:
    aliased = dict(data)
    for security_name, sysmon_name in _SECURITY_FIELD_ALIASES.items():
        if security_name in data and sysmon_name not in aliased:
            aliased[sysmon_name] = data[security_name]
    return aliased


_SECURITY_EVENT_ID_DISPATCH: dict[int, Callable[[dict[str, str | None]], dict]] = {
    # 4688 (process creation): reuses the Sysmon extractor verbatim -- the
    # aliasing above has already renamed the Security fields onto the
    # Image/CommandLine/User vocabulary it reads.
    4688: _normalize_process_creation,
}


def normalize_event(record: dict) -> NormalizedEvent:
    event = record.get("Event")
    if not isinstance(event, dict):
        raise EventNormalizationError("record missing 'Event' block")
    system = event.get("System")
    if not isinstance(system, dict):
        raise EventNormalizationError("record missing 'Event.System' block")

    host = _extract_host(system)
    timestamp = _extract_timestamp(system)
    event_id = _extract_event_id(system)
    channel = _extract_channel(system)

    data = _data_dict(event.get("EventData"))
    if event_id == 2:
        data = _flag_timestomp(data)

    if canonical_channel(channel) == "security":
        data = _apply_security_aliases(data)
        extractor = _SECURITY_EVENT_ID_DISPATCH.get(event_id)
    else:
        extractor = _SYSMON_EVENT_ID_DISPATCH.get(event_id)
    type_fields = extractor(data) if extractor else {}

    return NormalizedEvent(
        host=host,
        timestamp=timestamp,
        event_id=event_id,
        channel=channel,
        raw=record,
        event_data=data,
        **type_fields,
    )


def normalize_events(records: Iterable[dict]) -> Iterator[NormalizedEvent]:
    for record in records:
        yield normalize_event(record)
