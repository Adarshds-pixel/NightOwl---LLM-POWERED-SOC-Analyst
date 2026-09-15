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


def _extract_event_record_id(system: dict) -> int | None:
    """Non-raising, same posture as _extract_channel: EventRecordID backs
    ingest-time duplicate detection (event_service.py), not required to
    build a valid Event row, so a record missing or carrying an
    unparseable one still normalizes -- it just can never be deduplicated
    against a re-upload."""
    raw_record_id = system.get("EventRecordID")
    if raw_record_id is None:
        return None
    try:
        return int(raw_record_id)
    except (TypeError, ValueError):
        return None


# The single source of truth for "which channel is this," in scoping terms:
# canonical token -> the lowercase substring of the raw `System.Channel`
# string that identifies it. Real observed values (verified against actual
# sample files, not assumed): Sysmon -> 'Microsoft-Windows-Sysmon/Operational'
# (contains "sysmon"), Security -> 'Security' (contains "security"),
# PowerShell -> 'Microsoft-Windows-PowerShell/Operational' (contains
# "powershell", verified against 3 real 4104 samples, 2026-09-05), System ->
# 'System' (contains "system", verified against the real Event ID 7045
# record in ID7045-4697-SMBexec service registration.evtx, 2026-09-06 --
# before this entry, a 7045 event's channel canonicalized to None and
# silently fell through to the Sysmon dispatch table in normalize_event()
# below; System carries no dedicated dispatch table since its raw
# EventData fields already land in event_data unconditionally, same as the
# empty-but-present PowerShell dispatch table).
#
# Bits -> 'Microsoft-Windows-Bits-Client/Operational' (contains "bits") and
# Application -> 'Application' (contains "application") were added
# 2026-09-07 after a corpus-wide scan of all 80 real EVTX fixtures found
# 1,537 and 361 real events respectively canonicalizing to None -- i.e.
# silently unrecognized, not merely uncovered by a rule. This is a
# categorization/labeling fix only: recognizing these channels does not by
# itself create rule coverage (covered_event_ids() in detection/engine.py
# still requires an actual loaded rule per (channel, event_id) pair); it
# only stops a real, named channel from being mislabeled as unrecognized,
# which matters for correct channel-scoped rule matching if/when a rule
# for either channel is ever added, and for accurate "Channels" reporting
# in the Telemetry profile UI. No rules were added for either channel --
# see this dict's own scoping contract: a rule's `logsource.service` still
# has to name one of these tokens before it can evaluate anything on it.
#
# Deliberately NOT added: the 29,109-event "None" channel bucket from the
# same scan is not an unrecognized channel name -- it is one file,
# CA_PetiPotam_etw_rpc_efsr_5_6.evtx, whose raw records are a captured ETW
# trace (Provider.@Name is empty, Channel is genuinely absent/null,
# EventID is 0), not standard Windows Event Log channel telemetry at all.
# ETW trace records have no Channel to recognize -- there is no substring
# to add here, and EventID 0 carries no rule-evaluable semantics. This
# stays correctly unrecognized/uncovered rather than being forced into a
# model it doesn't fit.
#
# Every call site that needs a channel-scoping decision (rule_loader.py,
# engine.py, this module's own per-channel dispatch, event_service.py's
# SQL-level coverage filter) must derive from this one table rather than
# re-hardcoding a channel string comparison independently.
CHANNEL_TOKEN_SUBSTRINGS: dict[str, str] = {
    "sysmon": "sysmon",
    "security": "security",
    "powershell": "powershell",
    "system": "system",
    "bits": "bits",
    "application": "application",
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


# Synthetic key for legacy classic-EVT EventData: a manifest-free provider
# (verified real case: MsiInstaller's 1040/1042 "began/ended a transaction"
# events) renders its EventData as one or more *unnamed* positional
# `<Data>` values instead of Sysmon's `<Data Name="X">value</Data>` shape --
# xmltodict collapses a single such element to a plain string, and 2+
# unnamed siblings to a list of plain strings, never producing the
# {"@Name": ..., "#text": ...} shape the loop below reads. Previously this
# hit the same `else: return {}` branch as genuinely absent EventData,
# silently discarding real telemetry -- confirmed live on
# `rogue_msi_url_1040_1042.evtx`, where the dropped content included a live
# attacker-controlled MSI install-source URL
# (http://officemysuppbox.com/staterepository) that never reached detection
# or the AI second-opinion pass as a result. Positional values carry no
# reliable field semantics without the provider's message-format resource
# (not available here), so they are preserved verbatim under this one
# synthetic key rather than split into invented field names -- this is a
# provenance/housekeeping key, not a claim about what the data means, same
# spirit as the existing synthetic `TimestompSuspected` key below. Chosen to
# be unmistakably synthetic (no real Sysmon/Security field is named this)
# so it can never collide with or be confused for genuine EventData.
_UNNAMED_DATA_KEY = "UnnamedEventData"


def _data_dict(event_data: dict | None) -> dict[str, str | None]:
    """Flattens Sysmon's `EventData.Data[@Name=...]` elements into a plain
    {name: value} dict, tolerating xmltodict's shape quirks: a single
    `<Data>` element parses to a dict (not a list), 2+ parse to a list, and
    an empty `<Data Name="X"/>` has no "#text" key at all (-> None).

    A third real shape, handled separately: legacy classic-EVT providers
    with no `@Name` attribute at all render as a plain string (one `<Data>`
    element) or a list of plain strings (2+ unnamed siblings) -- see
    `_UNNAMED_DATA_KEY`'s comment for why these are preserved rather than
    dropped, and under one synthetic key rather than invented field names.
    Genuinely absent EventData (event_data is None/empty, or has no "Data"
    key at all) still returns {} -- there is nothing to preserve.
    """
    if not event_data:
        return {}
    data = event_data.get("Data")
    if data is None:
        return {}
    if isinstance(data, str):
        return {_UNNAMED_DATA_KEY: data} if data else {}
    if isinstance(data, dict):
        items = [data]
    elif isinstance(data, list):
        items = data
    else:
        return {}

    result: dict[str, str | None] = {}
    unnamed_values: list[str] = []
    for item in items:
        if isinstance(item, str):
            if item:
                unnamed_values.append(item)
            continue
        if not isinstance(item, dict):
            continue
        name = item.get("@Name")
        if name is None:
            continue
        result[name] = item.get("#text")
    if unnamed_values:
        result[_UNNAMED_DATA_KEY] = "\n".join(unnamed_values)
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
        "parent_process": data.get("ParentImage"),
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
# Image/ParentImage/CommandLine/User. Only applied for `channel ==
# "security"` (see normalize_event()), so a Sysmon record's own `Image`
# etc. is never touched.
#
# Verification status, checked against the one real 4688 sample in the
# whole 39-file corpus (`LM_WMIC_4648_rpcss.evtx`, 2026-09-05 -- pending.md
# previously flagged this table as "wired up but unverified", this is that
# check): its real EventData fields are exactly SubjectUserSid,
# SubjectUserName, SubjectDomainName, SubjectLogonId, NewProcessId,
# NewProcessName, TokenElevationType, ProcessId, CommandLine (present as a
# key but empty -- "Include command line in process creation events"
# wasn't enabled on that capture).
#   - "NewProcessName" -> "Image": VERIFIED (real value
#     "C:\Windows\System32\wbem\WMIC.exe").
#   - "SubjectUserName" -> "User": VERIFIED (real value "user01").
#   - "ProcessCommandLine" -> "CommandLine": the real field is already
#     named plain "CommandLine" -- this alias's own premise (that it's
#     sometimes called "ProcessCommandLine" instead) never matched
#     anything in the one sample checked, so it's presently inert, not
#     confirmed. Harmless either way: if the premise is simply wrong, nothing
#     fires; if some other real 4688 capture genuinely does use that name,
#     this is ready for it.
#   - "ParentProcessName" -> "ParentImage": NOT PRESENT in the sample at
#     all, and not part of the standard 4688 field set Microsoft documents
#     -- a bare 4688 only carries the *creator's* `ProcessId` (a PID, not a
#     resolved name), never a parent process name/path. Kept rather than
#     removed since it's harmless dead weight (same reasoning as above),
#     but do not treat this as a validated mapping.
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

# PowerShell/Operational channel -- Event ID 4104 ("Execute a Remote
# Command"/Script Block Logging). No extractor promotes a universal field
# (process/command_line/user) here: a real 4104 record's EventData carries
# no Image/CommandLine-shaped field at all (verified against 3 real
# samples, 2026-09-05 -- MessageNumber, MessageTotal, ScriptBlockText,
# ScriptBlockId, Path only), so inventing one would mean guessing rather
# than reading real data. `ScriptBlockText` still reaches rules and the UI
# through `event_data` -- normalize_event() always populates that dict
# regardless of whether a dispatch entry exists (see NormalizedEvent's own
# `event_data` field comment) -- so no dispatch entry is needed for
# detection to work; this table is currently empty on purpose, not a stub.
_POWERSHELL_EVENT_ID_DISPATCH: dict[int, Callable[[dict[str, str | None]], dict]] = {}

# Which dispatch table applies to a given canonical channel token. `None`
# (channel unrecognized, or Sysmon's own token) falls through to the Sysmon
# table -- Sysmon is the one channel this project supported before channel-
# awareness existed at all, so it's the correct default for anything not
# explicitly Security/PowerShell, matching every existing real fixture.
_CHANNEL_DISPATCH_TABLES: dict[str | None, dict[int, Callable[[dict[str, str | None]], dict]]] = {
    "security": _SECURITY_EVENT_ID_DISPATCH,
    "powershell": _POWERSHELL_EVENT_ID_DISPATCH,
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
    event_record_id = _extract_event_record_id(system)

    data = _data_dict(event.get("EventData"))
    if event_id == 2:
        data = _flag_timestomp(data)

    token = canonical_channel(channel)
    if token == "security":
        data = _apply_security_aliases(data)
    dispatch = _CHANNEL_DISPATCH_TABLES.get(token, _SYSMON_EVENT_ID_DISPATCH)
    extractor = dispatch.get(event_id)
    type_fields = extractor(data) if extractor else {}

    return NormalizedEvent(
        host=host,
        timestamp=timestamp,
        event_id=event_id,
        channel=channel,
        event_record_id=event_record_id,
        raw=record,
        event_data=data,
        **type_fields,
    )


def normalize_events(records: Iterable[dict]) -> Iterator[NormalizedEvent]:
    for record in records:
        yield normalize_event(record)
