"""Behavioural features for the ML anomaly layer.

The unit of analysis is a *window*: all events of ONE log family (Security,
Sysmon, PowerShell, System or Application) from ONE host within one
10-minute bucket. That is exactly what a single uploaded EVTX file yields --
one file is one channel -- so the model is trained on the same shape of data
it scores. (The previous design trained on windows that merged every channel
of a host and then scored single-channel uploads, which made any ordinary
Security-only upload look anomalous.)

Every feature is keyed on the family, never on a bare event id: event ids
collide across channels (Sysmon 1 is process creation, System 1 is a clock
change), so a channel-blind count mixes unrelated things.

Per family the vector is:
  * the composition of the window -- log counts of the family's most common
    event ids (its *vocabulary*, learned from the benign baseline and stored
    with the model) plus an "other" bucket;
  * size and diversity -- total events, distinct event ids;
  * a few family-specific behaviour counts (failed logons, distinct
    processes, network destinations, script block volume, ...).
Event ids never seen in the baseline are reported separately as
`novel_event_ids` -- they have no variance to model, so they are surfaced as
evidence instead of being forced into the covariance.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta

from app.ingestion.normalizer import canonical_channel
from app.schemas.event import NormalizedEvent

WINDOW = timedelta(minutes=10)
FAMILIES = ("security", "sysmon", "powershell", "system", "application")
VOCABULARY_SIZE = 15

_FAILED_LOGON_IDS = frozenset({4625, 4771, 4776})


def family_of(event: NormalizedEvent) -> str | None:
    family = canonical_channel(event.channel)
    return family if family in FAMILIES else None


def window_start(timestamp: datetime) -> datetime:
    return timestamp.replace(minute=(timestamp.minute // 10) * 10, second=0, microsecond=0)


def _distinct(values) -> int:
    return len({v for v in values if v not in (None, "", "-")})


def _semantic_features(family: str, events: list[NormalizedEvent]) -> dict[str, float]:
    data = [e.event_data or {} for e in events]
    if family == "security":
        logons = [d for e, d in zip(events, data) if e.event_id in (4624, 4625)]
        return {
            "failed_logons": float(sum(1 for e in events if e.event_id in _FAILED_LOGON_IDS)),
            "distinct_logon_accounts": float(_distinct(d.get("TargetUserName") for d in logons)),
            "distinct_logon_sources": float(_distinct(d.get("IpAddress") for d in logons)),
            "remote_logons": float(sum(1 for d in logons if str(d.get("LogonType")) in ("3", "10"))),
            "explicit_credential_logons": float(sum(1 for e in events if e.event_id == 4648)),
            "account_changes": float(sum(1 for e in events if 4720 <= e.event_id <= 4767 or e.event_id == 4781)),
            "distinct_new_processes": float(_distinct(e.process for e in events if e.event_id == 4688)),
        }
    if family == "sysmon":
        procs = [e for e in events if e.event_id == 1]
        net = [e for e in events if e.event_id == 3]
        return {
            "process_creations": float(len(procs)),
            "distinct_processes": float(_distinct((e.process or "").lower() for e in procs)),
            "distinct_parent_child": float(_distinct(f"{e.parent_process}>{e.process}".lower() for e in procs)),
            "network_connections": float(len(net)),
            "distinct_destinations": float(_distinct(e.destination_ip for e in net)),
            "distinct_destination_ports": float(_distinct(e.destination_port for e in net)),
            "distinct_access_targets": float(
                _distinct((d.get("TargetImage") or "").lower() for e, d in zip(events, data) if e.event_id == 10)
            ),
        }
    if family == "powershell":
        blocks = [d.get("ScriptBlockText") or "" for e, d in zip(events, data) if e.event_id == 4104]
        return {
            "script_blocks": float(len(blocks)),
            "script_chars": float(sum(len(b) for b in blocks)),
            "max_script_chars": float(max((len(b) for b in blocks), default=0)),
        }
    if family == "system":
        return {
            "service_installs": float(sum(1 for e in events if e.event_id == 7045)),
            "service_state_changes": float(sum(1 for e in events if e.event_id in (7036, 7040))),
        }
    return {}


def build_vocabulary(windows: list[list[NormalizedEvent]], size: int = VOCABULARY_SIZE) -> list[int]:
    """The `size` event ids most frequent across a family's benign windows."""
    counts: Counter[int] = Counter()
    for events in windows:
        counts.update(e.event_id for e in events)
    return [event_id for event_id, _ in counts.most_common(size)]


def extract_features(family: str, events: list[NormalizedEvent], vocabulary: list[int]) -> dict[str, float]:
    """One window's feature dict. Raw counts; the detector applies log1p."""
    counts = Counter(e.event_id for e in events)
    known = set(vocabulary)
    features: dict[str, float] = {f"eid_{event_id}": float(counts.get(event_id, 0)) for event_id in vocabulary}
    features["eid_other"] = float(sum(c for event_id, c in counts.items() if event_id not in known))
    features["total_events"] = float(len(events))
    features["distinct_event_ids"] = float(len(counts))
    features.update(_semantic_features(family, events))
    return features


def novel_event_ids(events: list[NormalizedEvent], seen_event_ids: set[int]) -> list[int]:
    return sorted({e.event_id for e in events} - seen_event_ids)
