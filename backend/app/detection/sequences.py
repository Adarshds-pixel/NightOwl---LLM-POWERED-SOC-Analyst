"""The small, exactly-3-pattern sequence engine (pending.md item 5 /
final_plan.md Phase 5).

`detection/engine.py::evaluate_event()` is deliberately single-event-scoped
(see its own docstring) -- neither it nor a Sigma YAML rule can express "did
event A, then event B, then event C happen together," or "did N different
things happen from the same source within a window." This module is a
small, hand-written, purpose-built detector for exactly the patterns real
corpus fixtures structurally need that for -- not a general sequence DSL.
Three so far: Process Herpaderping, an SMB share-enumeration probe, and a
Kerberos password spray (added 2026-09-05: `kerberos_pwd_spray_4771.evtx`
carries 9 real 4768s + 2 real 4771s, 10 distinct target usernames from one
source IP within 23ms -- exactly the "future build_failure_matrix.py run
surfaces a third sequence-dependent miss" trigger this module's own
docstring said to wait for, not built speculatively ahead of it). If a
future run surfaces a fourth, extend this file then, with the same
real-field-verification discipline, not speculatively now.

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
    tactics=["defense_evasion", "privilege_escalation"],
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

# rule_id -> SequencePattern, for any read path that resolves an Alert's
# rule_id to a human title/technique but only ever queried
# rule_loader.get_loaded_rules() before (routes_alerts.py, routes_events.py,
# routes_incidents.py) -- merge this in alongside that lookup.
SEQUENCE_PATTERNS: dict[str, SequencePattern] = {
    PROCESS_HERPADERPING.rule_id: PROCESS_HERPADERPING,
    SMB_SHARE_ENUM_PROBE.rule_id: SMB_SHARE_ENUM_PROBE,
    KERBEROS_PASSWORD_SPRAY.rule_id: KERBEROS_PASSWORD_SPRAY,
}

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

            matches.append((pipe_event, _match(SMB_SHARE_ENUM_PROBE)))
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
    )
