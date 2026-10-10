"""Plain names for Windows event ids, per channel.

Event ids are only meaningful inside their channel (Sysmon 1 is a process
creation, System 1 is a clock change), so every lookup takes the canonical
channel token from normalizer.canonical_channel, never an id alone.

Used by the AI second opinion (services/ai_opinion_service.py): a model given a
bare `"event_id": 18` guesses what it means, and in the 10 Oct 2026 fixture
audit it described pipe *connections* as pipe *creation* and an account being
*enabled* (4722) as an account being *created*. It is told to use `event_type`
when present and never to guess, so the fix is to always have a name to give it.

These tables carry the same labels as frontend/src/lib/constants.ts
(SYSMON_/SECURITY_/POWERSHELL_/SYSTEM_/APPLICATION_EVENT_TYPE_LABELS) so the
AI text and the Logs page never use two names for one event. Change both together.
"""

SYSMON: dict[int, str] = {
    1: "Process Creation",
    2: "File Time Changed",
    3: "Network Connection",
    5: "Process Terminated",
    6: "Driver Loaded",
    7: "Image Loaded",
    8: "Remote Thread Created",
    10: "Process Access",
    11: "File Created",
    12: "Registry Key Create/Delete",
    13: "Registry Value Set",
    14: "Registry Rename",
    17: "Pipe Created",
    18: "Pipe Connected",
    19: "WMI Filter",
    20: "WMI Consumer",
    21: "WMI Binding",
    22: "DNS Query",
    23: "File Deleted",
}

SECURITY: dict[int, str] = {
    1102: "Audit Log Cleared",
    4624: "Logon",
    4625: "Failed Logon",
    4627: "Group Membership Information for a Logon",
    4634: "Logoff",
    4648: "Explicit-Credential Logon",
    4656: "Object Handle Requested",
    4661: "SAM Object Handle",
    4662: "Directory Object Operation",
    4663: "Object Access",
    4672: "Special Privileges Assigned",
    4688: "Process Creation",
    4697: "Service Installed",
    4698: "Scheduled Task Created",
    4699: "Scheduled Task Deleted",
    4702: "Scheduled Task Updated",
    4719: "Audit Policy Changed",
    4720: "User Account Created",
    4722: "User Account Enabled",
    4724: "Password Reset Attempted",
    4728: "Member Added to Global Group",
    4732: "Member Added to Local Group",
    4738: "User Account Changed",
    4741: "Computer Account Created",
    4742: "Computer Account Changed",
    4743: "Computer Account Deleted",
    4756: "Member Added to Universal Group",
    4768: "Kerberos TGT Requested",
    4769: "Kerberos Service Ticket Requested",
    4771: "Kerberos Pre-auth Failed",
    4776: "NTLM Credential Validation",
    4781: "Account Renamed",
    4798: "User Group Membership Enumerated",
    4799: "Local Group Membership Enumerated",
    5136: "Directory Object Modified",
    5140: "Network Share Accessed",
    5145: "Network Share Object Access",
    5156: "Network Connection Allowed",
    5158: "Local Port Bind Allowed",
}

POWERSHELL: dict[int, str] = {
    4103: "PowerShell Module Logging",
    4104: "PowerShell Script Block",
}

SYSTEM: dict[int, str] = {
    104: "Event Log Cleared",
    7036: "Service State Changed",
    7040: "Service Start Type Changed",
    7045: "Service Installed",
}

APPLICATION: dict[int, str] = {
    1040: "MSI Transaction Started",
    1042: "MSI Transaction Ended",
    18456: "SQL Server Login Failed",
}

_BY_CHANNEL: dict[str, dict[int, str]] = {
    "sysmon": SYSMON,
    "security": SECURITY,
    "powershell": POWERSHELL,
    "system": SYSTEM,
    "application": APPLICATION,
}


def event_type_name(channel_token: str | None, event_id: int) -> str | None:
    """The name for this (channel, event id), or None when this project has no
    verified name for it -- callers must then refer to the event by channel and
    number only, never by an assumed category."""
    return _BY_CHANNEL.get(channel_token or "", {}).get(event_id)


# Well-known Windows RPC interface UUIDs -> the service behind them. In the 10
# Oct 2026 audit the AI review, shown raw RPC trace events next to a detection
# titled "EFSRPC (PetitPotam)...", twice announced that
# {367abb81-9844-35f1-ad32-98f038001003} "is the EFSRPC interface". It is the
# Service Control Manager. A model cannot know a UUID; it can only be told.
# Only interfaces documented in Microsoft's open protocol specifications
# ([MS-SCMR], [MS-EFSR], [MS-SAMR], [MS-LSAD], [MS-NRPC], [MS-DRSR], [MS-SRVS],
# [MS-WKST], [MS-RRP], [MS-TSCH], [MS-RPRN], [MS-EVEN], [C706] endpoint mapper)
# are listed; anything else stays unnamed.
RPC_INTERFACES: dict[str, str] = {
    "367abb81-9844-35f1-ad32-98f038001003": "Service Control Manager (svcctl)",
    "c681d488-d850-11d0-8c52-00c04fd90f7e": "Encrypting File System Remote Protocol (EFSRPC, lsarpc pipe)",
    "df1941c5-fe89-4e79-bf10-463657acf44d": "Encrypting File System Remote Protocol (EFSRPC, efsrpc pipe)",
    "12345778-1234-abcd-ef00-0123456789ac": "Security Account Manager (samr)",
    "12345778-1234-abcd-ef00-0123456789ab": "Local Security Authority (lsarpc)",
    "12345678-1234-abcd-ef00-01234567cffb": "Netlogon",
    "12345678-1234-abcd-ef00-0123456789ab": "Print Spooler (spoolss)",
    "e3514235-4b06-11d1-ab04-00c04fc2dcd2": "Directory Replication Service (drsuapi)",
    "4b324fc8-1670-01d3-1278-5a47bf6ee188": "Server Service (srvsvc)",
    "6bffd098-a112-3610-9833-46c3f87e345a": "Workstation Service (wkssvc)",
    "338cd001-2244-31f1-aaaa-900038001003": "Remote Registry (winreg)",
    "1ff70682-0a51-30e8-076d-740be8cee98b": "Task Scheduler (atsvc)",
    "86d35949-83c9-4044-b424-db363231fd0c": "Task Scheduler (ITaskSchedulerService)",
    "82273fdc-e32a-18c3-3f78-827929dc23ea": "Event Log (eventlog)",
    "e1af8308-5d1f-11c9-91a4-08002b14a0fa": "RPC Endpoint Mapper",
}


def rpc_interface_name(uuid: object) -> str | None:
    """The service behind an RPC interface UUID (braces and case ignored), or
    None for one not in the documented table above."""
    if not isinstance(uuid, str):
        return None
    return RPC_INTERFACES.get(uuid.strip().strip("{}").lower())
