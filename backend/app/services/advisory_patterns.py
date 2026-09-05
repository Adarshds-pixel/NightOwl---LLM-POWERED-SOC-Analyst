"""Narrow, verified-real event shapes that are too false-positive-prone for
a deterministic Sigma rule but worth surfacing to the existing LLM
second-opinion mechanism (ai_opinion_service.py) for a human to review --
never promoted to a rule, never an Alert/Incident, never a severity score.
See ai_opinion_service.py's module docstring for the advisory-vs-detection
boundary this module exists to preserve.

Each function here answers one question -- "does this single normalized
event match pattern X" -- so ingest_service.py can call them per-event in
its existing normalize/persist loop without a second pass over the file.
"""

from app.ingestion.normalizer import canonical_channel

# PowerView's Invoke-UserHunter / NetSessionEnum discovery technique: the
# System process opening a named pipe to \lsass or \srvsvc over SMB.
# Verified real content (Discovery_Remote_System_NamedPipes_Sysmon_18.evtx,
# discovery_sysmon_18_Invoke_UserHunter_NetSessionEnum_DC-srvsvc.evtx):
# PipeName is the bare literal name, not GUID-prefixed like the spoolss
# rule's samples. Deliberately not a rule: \srvsvc in particular is also
# common legitimate SMB/RPC traffic (share browsing, GPO refresh, remote
# admin tooling), so a blanket PipeName match would be a real
# false-positive machine -- flagging it for an advisory second look, not
# asserting it's malicious the way an Alert would.
_SENSITIVE_PIPE_NAMES = frozenset({"\\lsass", "\\srvsvc"})


def is_named_pipe_discovery(channel: str | None, event_id: int, event_data: dict) -> bool:
    if canonical_channel(channel) != "sysmon" or event_id != 18:
        return False
    if event_data.get("Image") != "System":
        return False
    return event_data.get("PipeName") in _SENSITIVE_PIPE_NAMES
