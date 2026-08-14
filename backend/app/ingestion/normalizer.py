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
from datetime import datetime

from app.schemas.event import NormalizedEvent


class EventNormalizationError(Exception):
    pass


def _extract_host(system: dict) -> str:
    host = system.get("Computer")
    if not isinstance(host, str) or not host:
        raise EventNormalizationError("record missing 'System.Computer'")
    return host


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


def _normalize_file_create(data: dict[str, str | None]) -> dict:
    return {
        "process": data.get("Image"),
        "user": data.get("User"),
        "target_filename": data.get("TargetFilename"),
    }


_EVENT_ID_DISPATCH: dict[int, Callable[[dict[str, str | None]], dict]] = {
    1: _normalize_process_creation,
    3: _normalize_network_connection,
    11: _normalize_file_create,
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

    data = _data_dict(event.get("EventData"))
    extractor = _EVENT_ID_DISPATCH.get(event_id)
    type_fields = extractor(data) if extractor else {}

    return NormalizedEvent(host=host, timestamp=timestamp, event_id=event_id, raw=record, **type_fields)


def normalize_events(records: Iterable[dict]) -> Iterator[NormalizedEvent]:
    for record in records:
        yield normalize_event(record)
