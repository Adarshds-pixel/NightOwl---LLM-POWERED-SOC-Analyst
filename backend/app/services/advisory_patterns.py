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


# Security Event ID 4697 ("a service was installed on the system"). The
# project's one loaded rule for this event id
# (detection/rules/kernel_driver_service_installed.yml) deliberately only
# fires when ServiceType is kernel driver (0x00000001) -- see that rule's
# own description for why: this project's entire real fixture corpus has
# exactly 4 real 4697 samples, all malicious, with no benign 4697 capture
# anywhere to bound a broader rule's false-positive rate against. Every
# ServiceType other than kernel driver -- by far the common case, including
# 3 of those 4 real malicious samples -- is evaluated by that rule's
# logsource but never matched by its condition, and was previously reported
# as "covered, clean" with zero further scrutiny. Proven live, 2026-09-11:
# `ID4697-MSF payload deployed via service.evtx` (an obfuscated-PowerShell
# Metasploit service stager, ServiceType 0x00000010) showed a green
# "no known malicious activity" verdict at 100% coverage, and because
# coverage read 100%, the existing uncovered-events AI-opinion trigger
# never engaged either -- the payload was invisible to both layers.
#
# This stays the mirror-image complement of the existing rule's own scope
# (anything the rule structurally cannot judge), not a content-based
# heuristic (ServiceFileName keywords, ServiceAccount, etc.) -- the same
# "no benign corpus to validate against" guardrail applies here identically
# to why the rule itself stays narrow. Event 4697 is also inherently rare
# in real telemetry (confirmed: 0 occurrences across the entire 40-file
# real-PC NightOwl-Benign-Dataset sweep, 2026-09-11), so this is
# self-bounding the same way is_named_pipe_discovery already is -- "always
# few in practice," not a broad trigger that could fire often or drive up
# LLM call volume.
_KERNEL_DRIVER_SERVICE_TYPE = "0x00000001"


def is_non_kernel_driver_service_installation(channel: str | None, event_id: int, event_data: dict) -> bool:
    if canonical_channel(channel) != "security" or event_id != 4697:
        return False
    service_type = event_data.get("ServiceType")
    if service_type is None:
        return False
    return service_type != _KERNEL_DRIVER_SERVICE_TYPE
