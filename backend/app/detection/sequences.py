"""Multi-event sequence detectors.

`detection/engine.py::evaluate_event()` is deliberately single-event-scoped
-- neither it nor a Sigma YAML rule can express "did event A, then event B,
then event C happen together," or "did N different things happen from the
same source within a window." This module is a small, hand-written detector
for exactly the patterns real corpus fixtures need -- not a general sequence
DSL. Eight patterns (see SEQUENCE_PATTERNS): Process Herpaderping, an SMB
share-enumeration probe, Kerberos password spray, authentication brute
force, remote SAM/LSA enumeration, mass process access, group self-add and
bulk group-membership addition. Each was added only once a real capture
needed it, with thresholds checked against the benign corpus.

Scope, explicitly: each detector only looks within the current ingest
batch (the same `records` one `POST /ingest` call parses), never a
re-scan of previously-persisted events. Both real corpus fixtures carry
their entire sequence in one file, so this doesn't affect passing them --
but a sequence whose parts arrive across two separate uploads would not
be caught. Documented, not silently assumed.

Each match is built as a real `RuleMatch` (detection/engine.py) so
`ingest_service.py` can hand it to the exact same
`incident_service.find_or_create_incident` + `detection_service.save_alerts`
path a normal rule match already uses -- no parallel Alert/Incident
creation logic. The one integration seam this needs: a sequence's
`rule_id` is not in `rule_loader.get_loaded_rules()` (it was never a YAML
file), so anything that resolves an Alert's rule_id to a human title/
technique (routes_alerts.py, routes_events.py, routes_incidents.py) must
also consult `SEQUENCE_PATTERNS` below.
"""

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

from app.detection.engine import RuleMatch
from app.ingestion.normalizer import canonical_channel
from app.models.event import Event
from app.schemas.event import NormalizedEvent
from app.services import severity_service

EventRow = tuple[Event, NormalizedEvent]


@dataclass(frozen=True)
class SequencePattern:
    """The title/technique/severity a matched sequence carries -- the
    hand-written counterpart to a YAML rule's front matter, since a
    sequence has no rule file for rule_loader.py to parse these from."""

    rule_id: str
    title: str
    technique_id: str
    tactics: list[str]
    level: str


PROCESS_HERPADERPING = SequencePattern(
    rule_id="sequence-process-herpaderping",
    title="Process Herpaderping (File Create -> Process Access -> Image Load Chain)",
    # No dedicated ATT&CK sub-technique exists for Process Herpaderping;
    # T1055 (Process Injection) is the real, validated parent technique
    # its own defense-evasion/privilege-escalation family (Process
    # Hollowing T1055.012, Process Doppelganging T1055.013, ...) belongs
    # to -- confirmed present in this project's loaded MITRE dataset via
    # app.mitre.loader.load_mitre_techniques(), not guessed.
    technique_id="T1055",
    tactics=["stealth", "privilege_escalation"],
    level="high",
)

SMB_SHARE_ENUM_PROBE = SequencePattern(
    rule_id="sequence-smb-share-enum-probe",
    title="SMB Share Enumeration Probe (Remote Connection + Server Service Pipe)",
    technique_id="T1135",  # Network Share Discovery -- confirmed in the loaded MITRE dataset.
    tactics=["discovery"],
    level="low",
)

KERBEROS_PASSWORD_SPRAY = SequencePattern(
    rule_id="sequence-kerberos-password-spray",
    title="Kerberos Password Spray (Multiple Distinct Accounts from One Source)",
    technique_id="T1110.003",  # Password Spraying -- confirmed in the loaded MITRE dataset.
    tactics=["credential_access"],
    level="high",
)

AUTHENTICATION_BRUTE_FORCE = SequencePattern(
    rule_id="sequence-authentication-brute-force",
    title="Authentication Brute Force (Repeated Failed Logons from One Source)",
    technique_id="T1110",  # Brute Force
    tactics=["credential_access"],
    level="medium",
)

REMOTE_SAM_ENUMERATION = SequencePattern(
    rule_id="sequence-remote-sam-lsa-enumeration",
    title="Remote SAM/LSA/Server Service Enumeration over IPC$ (BloodHound / net-style recon)",
    technique_id="T1087",  # Account Discovery
    tactics=["discovery"],
    level="low",
)

MASS_PROCESS_ACCESS = SequencePattern(
    rule_id="sequence-mass-process-access",
    title="Process Discovery by Mass Process Access from a Non-System Binary",
    technique_id="T1057",  # Process Discovery
    tactics=["discovery"],
    level="low",
)

GROUP_SELF_ADD = SequencePattern(
    rule_id="sequence-group-self-add",
    title="Account Added Itself to a Security Group",
    technique_id="T1098",  # Account Manipulation
    tactics=["persistence", "privilege_escalation"],
    level="medium",
)

BULK_GROUP_ADDITION = SequencePattern(
    rule_id="sequence-bulk-group-membership-addition",
    title="One Account Added Members to Many Security Groups in a Short Time",
    technique_id="T1098",  # Account Manipulation
    tactics=["persistence", "privilege_escalation"],
    level="medium",
)

# The (channel token, event id) pairs the detectors above read. Coverage
# reporting counts these as CHECKED: before, a failed logon (4625) or a Kerberos
# event (4768/4771) was reported as "no rule coverage" although the brute-force
# and password-spray detectors evaluate it on every upload.
SEQUENCE_INPUTS: frozenset[tuple[str | None, int]] = frozenset(
    {("sysmon", event_id) for event_id in (3, 7, 10, 11, 18)}
    | {("security", event_id) for event_id in (4625, 4728, 4732, 4756, 5145)}
    | {("security", event_id) for event_id in (4768, 4771)}
    | {("application", 18456)}
)

SMB_FAN_OUT = SequencePattern(
    rule_id="sequence-smb-fan-out",
    title="SMB Fan-Out (One Process Connecting to Many Hosts on Port 445)",
    technique_id="T1018",  # Remote System Discovery
    tactics=["discovery"],
    level="low",
)

# rule_id -> SequencePattern, for any read path that resolves an Alert's
# rule_id to a human title/technique but only ever queried
# rule_loader.get_loaded_rules() before (routes_alerts.py, routes_events.py,
# routes_incidents.py) -- merge this in alongside that lookup.
SEQUENCE_PATTERNS: dict[str, SequencePattern] = {
    PROCESS_HERPADERPING.rule_id: PROCESS_HERPADERPING,
    SMB_SHARE_ENUM_PROBE.rule_id: SMB_SHARE_ENUM_PROBE,
    KERBEROS_PASSWORD_SPRAY.rule_id: KERBEROS_PASSWORD_SPRAY,
    AUTHENTICATION_BRUTE_FORCE.rule_id: AUTHENTICATION_BRUTE_FORCE,
    REMOTE_SAM_ENUMERATION.rule_id: REMOTE_SAM_ENUMERATION,
    MASS_PROCESS_ACCESS.rule_id: MASS_PROCESS_ACCESS,
    GROUP_SELF_ADD.rule_id: GROUP_SELF_ADD,
    BULK_GROUP_ADDITION.rule_id: BULK_GROUP_ADDITION,
    SMB_FAN_OUT.rule_id: SMB_FAN_OUT,
}

# SMB fan-out: one process on one host opening port-445 connections to this
# many DISTINCT addresses within the window. UserHunter / share scanners touch
# a whole subnet in seconds; an ordinary client talks to one or two file
# servers. Measured on the benign corpus: 106 Sysmon network events, none on
# port 445 -- so the threshold is a conservative judgement, not a calibrated
# one. Backup or management servers that legitimately fan out will trip it,
# which is why it is low severity. Re-calibrate when more benign network data
# is collected (see ML.md "How to make it better").
_SMB_FAN_OUT_WINDOW = timedelta(seconds=60)
_SMB_FAN_OUT_DISTINCT_HOSTS = 5

# 4728 / 4732 / 4756: member added to a global / local / universal security group.
_GROUP_ADD_EVENT_IDS = frozenset({4728, 4732, 4756})
# Bulk additions: one subject adding members to this many distinct groups
# within the window. Onboarding one user touches a handful of groups at
# most; scripted privilege staging touches many at once.
_BULK_GROUP_WINDOW = timedelta(minutes=10)
_BULK_GROUP_DISTINCT_GROUPS = 5

# Brute force: this many failed authentications from one source within the
# window. A user mistyping a password produces 1-3; lockout policies
# typically trip at 5-10.
_BRUTE_FORCE_WINDOW = timedelta(minutes=5)
_BRUTE_FORCE_THRESHOLD = 8

# Remote enumeration: one (source address, user account) touching at least
# this many DISTINCT RPC pipes from the set below over IPC$ within the
# window, with at least _SAM_ENUM_MIN_ACCESSES accesses in total. Machine
# accounts ($) are excluded -- domain members talk to these pipes on their
# own all day. NOTE: on domain controllers with heavy legitimate admin
# tooling this can still be noisy; it is low severity for that reason.
_SAM_ENUM_WINDOW = timedelta(seconds=60)
_SAM_ENUM_PIPES = frozenset({"samr", "lsarpc", "srvsvc", "wkssvc"})
_SAM_ENUM_MIN_DISTINCT_PIPES = 3
_SAM_ENUM_MIN_ACCESSES = 5

# Mass process access: one non-system binary opening at least this many
# distinct processes within the window (a process listing done by opening
# every process -- e.g. Meterpreter's `ps`).
_MASS_ACCESS_WINDOW = timedelta(seconds=10)
_MASS_ACCESS_DISTINCT_TARGETS = 10
_SYSTEM_IMAGE_PREFIXES = (
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\programdata\\microsoft\\windows defender\\",
)

# Real observed gap between chained events in the verified fixture
# (DE_ProcessHerpaderping_Sysmon_11_10_1_7.evtx) is ~70ms end to end
# (FileCreate 10:17:18.369 -> ProcessAccess .377 -> ImageLoad .439) --
# 10 seconds is a generous margin for timing/logging jitter on a real
# system, not a loosely-guessed number.
_HERPADERPING_WINDOW = timedelta(seconds=10)

# Real observed gap in the verified fixture
# (discovery_enum_shares_target_sysmon_3_18.evtx) between the pipe
# connect (17:42:52.833/.848) and the first qualifying network
# connection (17:42:53.854) is ~1.02s. 60 seconds gives generous margin
# while still ruling out coincidentally pairing a share-enum pipe connect
# with a completely unrelated SMB connection from hours earlier in a
# long-running capture.
_SMB_ENUM_WINDOW = timedelta(seconds=60)

# Verified real content: PipeName == "\srvsvc" (Server Service -- the
# NetShareEnum/NetSessionEnum RPC endpoint) in the one real fixture this
# pattern is built from. \wkssvc/\browser are well-documented
# share/session-enumeration pipes too (PowerView's own tooling uses
# \wkssvc), but are deliberately NOT included here without a real sample
# to verify the *combination* against -- narrow-and-verified over
# broad-and-speculative, same discipline as everywhere else in this
# project. Extend when a real sample justifies it.
_DISCOVERY_PIPE_NAMES = frozenset({"\\srvsvc"})

# Real observed span in the verified fixture (kerberos_pwd_spray_4771.evtx)
# is ~23ms for all 11 events (7 unknown-account 4768s, 2 wrong-password
# 4771s, 2 successful 4768s) -- 60 seconds gives a generous margin for a
# real spray tool deliberately throttling itself to dodge lockout-count
# thresholds, while still being far too tight for a domain controller's
# own ambient traffic from the same client IP across a working day to
# ever cross it by coincidence.
_KERBEROS_SPRAY_WINDOW = timedelta(seconds=60)

# The verified fixture shows 10 distinct target usernames from one source
# IP within the window; 4 is deliberately well below that, not tuned to
# just barely catch this one sample -- a real client legitimately
# requesting Kerberos tickets for itself plus one or two service accounts
# in the same window (e.g. a scheduled task) still stays under this, while
# any burst that fans out across several different account names from a
# single source has no ordinary explanation.
_KERBEROS_SPRAY_DISTINCT_USER_THRESHOLD = 4

# 4768 (TGT request) and 4771 (pre-authentication failed) are both logged
# by the KDC for an AS-REQ -- the verified fixture's spray shows a mix of
# both (7x 4768 Status=0x6 "unknown principal" for invalid accounts, 2x
# 4771 Status=0x18 "preauth failed" for accounts that do exist), so both
# have to be in scope or half the real burst would be invisible to this
# detector.
_KERBEROS_EVENT_IDS = frozenset({4768, 4771})


def _basename(path: str | None) -> str | None:
    """Windows path -> lowercase filename, tolerating either separator or
    a bare filename with no path at all (real content: ProcessAccess's
    TargetImage is sometimes just "samir.exe", no path)."""
    if not path:
        return None
    return path.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def _is_sysmon(normalized: NormalizedEvent) -> bool:
    return canonical_channel(normalized.channel) == "sysmon"


def _is_security(normalized: NormalizedEvent) -> bool:
    return canonical_channel(normalized.channel) == "security"


def _normalize_ip(value: str | None) -> str | None:
    """Strips the IPv4-mapped-IPv6 "::ffff:" prefix so the same real
    source shows up as one grouping key, not two -- the verified fixture's
    own burst has exactly this: 9 of its 11 events carry a bare
    "172.16.66.1", the last carries "::ffff:172.16.66.1", both the same
    real client. Without this, a source whose OS/logging happens to
    switch representations mid-burst would silently split into two
    smaller, individually-below-threshold groups."""
    if not value:
        return None
    prefix = "::ffff:"
    return value[len(prefix):] if value.startswith(prefix) else value


def _severity(pattern: SequencePattern) -> tuple[str, int]:
    return (
        severity_service.compute_severity(pattern.level, pattern.tactics),
        severity_service.compute_severity_score(pattern.level, pattern.tactics),
    )


def _match(pattern: SequencePattern) -> RuleMatch:
    level, score = _severity(pattern)
    return RuleMatch(
        rule_id=pattern.rule_id,
        title=pattern.title,
        level=level,
        score=score,
        technique_id=pattern.technique_id,
    )


def _detect_process_herpaderping(rows: list[EventRow]) -> list[tuple[Event, RuleMatch]]:
    file_creates = [(e, n) for e, n in rows if _is_sysmon(n) and n.event_id == 11]
    process_accesses = [(e, n) for e, n in rows if _is_sysmon(n) and n.event_id == 10]
    image_loads = [(e, n) for e, n in rows if _is_sysmon(n) and n.event_id == 7]
    if not (file_creates and process_accesses and image_loads):
        return []

    matches: list[tuple[Event, RuleMatch]] = []
    matched_anchor_ids: set[int] = set()

    for _file_event, file_normalized in file_creates:
        target_basename = _basename(file_normalized.event_data.get("TargetFilename"))
        creator_guid = file_normalized.event_data.get("ProcessGuid")
        if not target_basename or not creator_guid:
            continue

        for access_event, access_normalized in process_accesses:
            if access_normalized.host != file_normalized.host:
                continue
            if access_normalized.event_data.get("SourceProcessGUID") != creator_guid:
                continue
            if _basename(access_normalized.event_data.get("TargetImage")) != target_basename:
                continue
            if not (file_normalized.timestamp <= access_normalized.timestamp <= file_normalized.timestamp + _HERPADERPING_WINDOW):
                continue
            accessed_guid = access_normalized.event_data.get("TargetProcessGUID")
            if not accessed_guid:
                continue

            for load_event, load_normalized in image_loads:
                if load_event.id in matched_anchor_ids:
                    continue
                if load_normalized.host != access_normalized.host:
                    continue
                if load_normalized.event_data.get("ProcessGuid") != accessed_guid:
                    continue
                loaded = load_normalized.event_data.get("ImageLoaded") or load_normalized.event_data.get("Image")
                if _basename(loaded) != target_basename:
                    continue
                if not (access_normalized.timestamp <= load_normalized.timestamp <= access_normalized.timestamp + _HERPADERPING_WINDOW):
                    continue

                matched_anchor_ids.add(load_event.id)
                matches.append((load_event, _match(PROCESS_HERPADERPING)))
                break  # this access/load pair is spent; move to the next process-access candidate

    return matches


def _detect_smb_share_enum_probe(rows: list[EventRow]) -> list[tuple[Event, RuleMatch]]:
    pipe_connects = [(e, n) for e, n in rows if _is_sysmon(n) and n.event_id == 18]
    network_connections = [(e, n) for e, n in rows if _is_sysmon(n) and n.event_id == 3]
    if not (pipe_connects and network_connections):
        return []

    matches: list[tuple[Event, RuleMatch]] = []
    last_alert_at: dict[str, object] = {}

    for pipe_event, pipe_normalized in pipe_connects:
        if pipe_normalized.event_data.get("PipeName") not in _DISCOVERY_PIPE_NAMES:
            continue

        for _net_event, net_normalized in network_connections:
            if net_normalized.host != pipe_normalized.host:
                continue
            initiated = (net_normalized.event_data.get("Initiated") or "").lower()
            if initiated != "false":
                continue
            if net_normalized.event_data.get("SourcePort") != "445":
                continue
            gap = abs((net_normalized.timestamp - pipe_normalized.timestamp).total_seconds())
            if gap > _SMB_ENUM_WINDOW.total_seconds():
                continue

            # One alert per host per window, not one per pipe connect.
            last = last_alert_at.get(pipe_normalized.host)
            if last is None or (pipe_normalized.timestamp - last) > _SMB_ENUM_WINDOW:
                matches.append((pipe_event, _match(SMB_SHARE_ENUM_PROBE)))
                last_alert_at[pipe_normalized.host] = pipe_normalized.timestamp
            break  # one corroborating connection is enough for this pipe connect

    return matches


def _detect_kerberos_password_spray(rows: list[EventRow]) -> list[tuple[Event, RuleMatch]]:
    kerberos_events = [(e, n) for e, n in rows if _is_security(n) and n.event_id in _KERBEROS_EVENT_IDS]
    if len(kerberos_events) < _KERBEROS_SPRAY_DISTINCT_USER_THRESHOLD:
        return []

    by_source: dict[tuple[str, str], list[EventRow]] = defaultdict(list)
    for event, normalized in kerberos_events:
        ip = _normalize_ip(normalized.event_data.get("IpAddress"))
        username = normalized.event_data.get("TargetUserName")
        if not ip or not username:
            continue
        # Failures only: a successful TGT request (Status 0x0) is a normal
        # logon, and counting them made any busy terminal server / NAT
        # address look like a spray. Machine accounts and krbtgt are not
        # spray targets.
        status = (normalized.event_data.get("Status") or "").lower()
        if normalized.event_id == 4768 and status in ("0x0", "0x00000000", ""):
            continue
        if username.endswith("$") or username.lower() == "krbtgt":
            continue
        if ip in ("::1", "127.0.0.1"):
            continue
        by_source[(normalized.host, ip)].append((event, normalized))

    matches: list[tuple[Event, RuleMatch]] = []
    for group in by_source.values():
        group.sort(key=lambda pair: pair[1].timestamp)

        # Sliding window over this one source's own events: at each new
        # event, drop anything older than the window relative to *that*
        # event, then check how many distinct usernames remain in view.
        # `armed` suppresses re-alerting on every subsequent event while
        # the burst stays above threshold -- one alert per burst, not one
        # per event in it -- but resets the moment the window drops back
        # below threshold, so a second, later burst from the same source
        # still gets its own alert.
        window: list[EventRow] = []
        armed = False
        for event, normalized in group:
            window.append((event, normalized))
            window[:] = [
                (e, n) for e, n in window if normalized.timestamp - n.timestamp <= _KERBEROS_SPRAY_WINDOW
            ]
            distinct_users = {n.event_data.get("TargetUserName") for _e, n in window}
            if len(distinct_users) >= _KERBEROS_SPRAY_DISTINCT_USER_THRESHOLD:
                if not armed:
                    matches.append((event, _match(KERBEROS_PASSWORD_SPRAY)))
                    armed = True
            else:
                armed = False

    return matches


_MSSQL_CLIENT_RE = re.compile(r"\[CLIENT:\s*([^\]\s]+)\s*\]", re.IGNORECASE)


def _failed_auth_source(normalized: NormalizedEvent) -> str | None:
    """Grouping key for a failed authentication, or None if `normalized` is
    not one: Security 4625 (failed Windows logon) keyed by source address
    (or target account for local logons with no address), MSSQL 18456
    (Application log) keyed by the [CLIENT: x] address in its message."""
    channel = canonical_channel(normalized.channel)
    if channel == "security" and normalized.event_id == 4625:
        ip = _normalize_ip(normalized.event_data.get("IpAddress"))
        if ip and ip not in ("-", "::1", "127.0.0.1"):
            return f"ip:{ip}"
        user = normalized.event_data.get("TargetUserName")
        return f"user:{user.lower()}" if user and user != "-" else None
    if channel == "application" and normalized.event_id == 18456:
        match = _MSSQL_CLIENT_RE.search(normalized.event_data.get("UnnamedEventData") or "")
        return f"mssql:{match.group(1)}" if match else None
    return None


def _sliding_bursts(group: list[EventRow], window: timedelta, is_burst) -> list[EventRow]:
    """One anchor per burst: walk `group` (time-ordered), keep the events
    within `window` of the newest, and report the event at which `is_burst`
    first becomes true; re-arm once the window falls back below it."""
    anchors: list[EventRow] = []
    in_view: list[EventRow] = []
    armed = False
    for event, normalized in group:
        in_view.append((event, normalized))
        in_view[:] = [(e, n) for e, n in in_view if normalized.timestamp - n.timestamp <= window]
        if is_burst(in_view):
            if not armed:
                anchors.append((event, normalized))
                armed = True
        else:
            armed = False
    return anchors


def _detect_authentication_brute_force(rows: list[EventRow]) -> list[tuple[Event, RuleMatch]]:
    by_source: dict[tuple[str, str], list[EventRow]] = defaultdict(list)
    for event, normalized in rows:
        key = _failed_auth_source(normalized)
        if key:
            by_source[(normalized.host, key)].append((event, normalized))
    matches: list[tuple[Event, RuleMatch]] = []
    for group in by_source.values():
        if len(group) < _BRUTE_FORCE_THRESHOLD:
            continue
        group.sort(key=lambda pair: pair[1].timestamp)
        for anchor, _n in _sliding_bursts(group, _BRUTE_FORCE_WINDOW, lambda view: len(view) >= _BRUTE_FORCE_THRESHOLD):
            matches.append((anchor, _match(AUTHENTICATION_BRUTE_FORCE)))
    return matches


def _detect_remote_sam_enumeration(rows: list[EventRow]) -> list[tuple[Event, RuleMatch]]:
    by_source: dict[tuple[str, str, str], list[EventRow]] = defaultdict(list)
    for event, normalized in rows:
        if not (_is_security(normalized) and normalized.event_id == 5145):
            continue
        data = normalized.event_data
        if not (data.get("ShareName") or "").upper().endswith("IPC$"):
            continue
        pipe = (data.get("RelativeTargetName") or "").lower()
        user = data.get("SubjectUserName") or ""
        if pipe not in _SAM_ENUM_PIPES or not user or user.endswith("$"):
            continue
        ip = _normalize_ip(data.get("IpAddress")) or "-"
        by_source[(normalized.host, ip, user.lower())].append((event, normalized))

    def _is_burst(view: list[EventRow]) -> bool:
        pipes = {(n.event_data.get("RelativeTargetName") or "").lower() for _e, n in view}
        return len(view) >= _SAM_ENUM_MIN_ACCESSES and len(pipes) >= _SAM_ENUM_MIN_DISTINCT_PIPES

    matches: list[tuple[Event, RuleMatch]] = []
    for group in by_source.values():
        group.sort(key=lambda pair: pair[1].timestamp)
        for anchor, _n in _sliding_bursts(group, _SAM_ENUM_WINDOW, _is_burst):
            matches.append((anchor, _match(REMOTE_SAM_ENUMERATION)))
    return matches


def _detect_mass_process_access(rows: list[EventRow]) -> list[tuple[Event, RuleMatch]]:
    by_source: dict[tuple[str, str], list[EventRow]] = defaultdict(list)
    for event, normalized in rows:
        if not (_is_sysmon(normalized) and normalized.event_id == 10):
            continue
        source = (normalized.event_data.get("SourceImage") or "").lower()
        if not source or source.startswith(_SYSTEM_IMAGE_PREFIXES):
            continue
        by_source[(normalized.host, source)].append((event, normalized))

    def _is_burst(view: list[EventRow]) -> bool:
        targets = {(n.event_data.get("TargetImage") or "").lower() for _e, n in view}
        return len(targets) >= _MASS_ACCESS_DISTINCT_TARGETS

    matches: list[tuple[Event, RuleMatch]] = []
    for group in by_source.values():
        if len(group) < _MASS_ACCESS_DISTINCT_TARGETS:
            continue
        group.sort(key=lambda pair: pair[1].timestamp)
        for anchor, _n in _sliding_bursts(group, _MASS_ACCESS_WINDOW, _is_burst):
            matches.append((anchor, _match(MASS_PROCESS_ACCESS)))
    return matches


def _detect_smb_fan_out(rows: list[EventRow]) -> list[tuple[Event, RuleMatch]]:
    by_process: dict[tuple[str, str], list[EventRow]] = defaultdict(list)
    for event, normalized in rows:
        if not (_is_sysmon(normalized) and normalized.event_id == 3):
            continue
        data = normalized.event_data
        if data.get("DestinationPort") != "445" or (data.get("Initiated") or "").lower() == "false":
            continue
        address = _normalize_ip(data.get("DestinationIp"))
        if not address or address in ("::1", "127.0.0.1"):
            continue
        by_process[(normalized.host, (data.get("Image") or "").lower())].append((event, normalized))

    def _is_burst(view: list[EventRow]) -> bool:
        return len({_normalize_ip(n.event_data.get("DestinationIp")) for _e, n in view}) >= _SMB_FAN_OUT_DISTINCT_HOSTS

    matches: list[tuple[Event, RuleMatch]] = []
    for group in by_process.values():
        if len(group) < _SMB_FAN_OUT_DISTINCT_HOSTS:
            continue
        group.sort(key=lambda pair: pair[1].timestamp)
        for anchor, _n in _sliding_bursts(group, _SMB_FAN_OUT_WINDOW, _is_burst):
            matches.append((anchor, _match(SMB_FAN_OUT)))
    return matches


def _detect_group_membership_abuse(rows: list[EventRow]) -> list[tuple[Event, RuleMatch]]:
    """Two checks a single Sigma rule cannot express: a field compared with
    another field (the subject adding ITSELF -- someone who can modify a
    group granting themselves its rights), and a volume of additions by one
    subject. Both exclude machine accounts and SYSTEM."""
    additions = [
        (e, n)
        for e, n in rows
        if _is_security(n) and n.event_id in _GROUP_ADD_EVENT_IDS
        and (n.event_data.get("SubjectUserSid") or "") not in ("", "S-1-5-18")
        and not (n.event_data.get("SubjectUserName") or "").endswith("$")
    ]
    matches: list[tuple[Event, RuleMatch]] = []
    by_subject: dict[tuple[str, str], list[EventRow]] = defaultdict(list)
    for event, normalized in additions:
        data = normalized.event_data
        if data.get("MemberSid") and data.get("MemberSid") == data.get("SubjectUserSid"):
            matches.append((event, _match(GROUP_SELF_ADD)))
        by_subject[(normalized.host, data["SubjectUserSid"])].append((event, normalized))

    def _is_burst(view: list[EventRow]) -> bool:
        return len({n.event_data.get("TargetSid") for _e, n in view}) >= _BULK_GROUP_DISTINCT_GROUPS

    for group in by_subject.values():
        group.sort(key=lambda pair: pair[1].timestamp)
        for anchor, _n in _sliding_bursts(group, _BULK_GROUP_WINDOW, _is_burst):
            matches.append((anchor, _match(BULK_GROUP_ADDITION)))
    return matches


def detect_sequences(rows: list[EventRow]) -> list[tuple[Event, RuleMatch]]:
    """Runs all three patterns over one ingest batch's (Event row,
    NormalizedEvent) pairs. Returns (anchor_event, RuleMatch) pairs in the
    same shape ingest_service.py's existing per-event rule-match loop
    already produces, so the caller can feed each straight into
    incident_service.find_or_create_incident + detection_service.save_alerts
    without new integration logic.
    """
    return (
        _detect_process_herpaderping(rows)
        + _detect_smb_share_enum_probe(rows)
        + _detect_kerberos_password_spray(rows)
        + _detect_authentication_brute_force(rows)
        + _detect_remote_sam_enumeration(rows)
        + _detect_mass_process_access(rows)
        + _detect_smb_fan_out(rows)
        + _detect_group_membership_abuse(rows)
    )
