# OS Credential Dumping Response Playbook
Technique: T1003

## Detection Context
Attackers dump credentials from LSASS memory, the SAM database, or NTDS.dit to obtain
password hashes or plaintext credentials for lateral movement and privilege escalation.
Common tooling includes Mimikatz, ProcDump (`procdump.exe -ma lsass.exe`), Task Manager
"Create dump file" on lsass.exe, and comsvcs.dll's `MiniDump` export invoked via
`rundll32.exe`. Sysmon signals: Event ID 10 (process access) with `TargetImage` =
`lsass.exe` and a `GrantedAccess` mask associated with memory-read rights (e.g. `0x1010`,
`0x1410`), especially when the `SourceImage` is not a known security/monitoring tool;
Event ID 1 process creation of `procdump.exe`, `rundll32.exe comsvcs.dll,MiniDump`, or
renamed Mimikatz binaries; Event ID 11 file creation of `.dmp` files in temp locations.

## Investigation Steps
1. Identify the source process that accessed `lsass.exe` and check whether it is a
   legitimate EDR/AV/monitoring tool or something unexpected.
2. Check the `GrantedAccess` value in the Event ID 10 record — full/read memory access
   combined with an unrecognized source process is a high-confidence indicator.
3. Search for any `.dmp` file created around the same time and where it was written to,
   moved to, or exfiltrated from.
4. Review the user context the source process ran under — dumping LSASS almost always
   requires local admin/SYSTEM, so confirm how that privilege was obtained.
5. Check for subsequent authentication events (e.g. Kerberos ticket use, NTLM auth) from
   the same host to other systems shortly after, which would indicate the dumped
   credentials are already being used for lateral movement.

## Containment
- Isolate the host immediately — this is a high-severity finding with lateral-movement
  potential.
- Kill the process that accessed LSASS and delete any generated dump file.
- Force a password reset for every credential that may have been resident in memory on
  that host (not just the logged-on user — cached domain admin creds are a common target).

## Remediation
- Enable LSA Protection (RunAsPPL) and Credential Guard where supported to block
  userland dumping tools.
- Restrict and monitor use of `procdump.exe` and similar sysinternals tools via
  application control.
- Rotate any potentially exposed service account and privileged credentials, not just
  the interactively logged-on user.
