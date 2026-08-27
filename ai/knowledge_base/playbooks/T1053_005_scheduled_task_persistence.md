# Scheduled Task Persistence Response Playbook
Technique: T1053.005

## Detection Context
Attackers create Scheduled Tasks (via `schtasks.exe`, `at.exe`, or direct registry/COM API
calls) to establish persistence or run payloads with elevated privileges at a chosen time or
trigger (logon, boot, idle). In Sysmon, this shows up as Event ID 1 process creation for
`schtasks.exe /create ...`, or Event ID 12/13/14 registry events under
`\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\`. Suspicious
indicators: task names mimicking legitimate Windows tasks but pointing to binaries in
`%TEMP%`, `%APPDATA%`, or `C:\Users\Public\`; tasks created by non-admin tooling; tasks
configured to run at logon/startup with hidden windows.

## Investigation Steps
1. Pull the full task definition (`schtasks /query /tn <name> /xml`) and inspect the
   `<Actions>` element for the executed command and arguments.
2. Check the task's creation time against the process creation event that made it, and
   identify the parent process/user context that issued the create command.
3. Verify whether the target binary path is a known-good, digitally signed Windows binary
   or an unsigned/unexpected file in a user-writable directory.
4. Search for other tasks created around the same time window on the same host or other
   hosts by the same actor/account (lateral persistence pattern).
5. Check the task's trigger and run-as-user — `SYSTEM`-level tasks created by a
   non-administrative user session are a strong red flag.

## Containment
- Disable/delete the malicious scheduled task (`schtasks /delete /tn <name> /f`).
- Quarantine the referenced binary/script before deletion for forensic preservation.
- Isolate the host if the task is confirmed to be executing attacker tooling.

## Remediation
- Audit all scheduled tasks on the host for other unauthorized entries.
- Restrict who can create tasks via Group Policy where feasible.
- Add detection coverage for task creation targeting user-writable directories.
