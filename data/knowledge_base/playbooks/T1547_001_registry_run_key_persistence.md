# Registry Run Key / Startup Persistence Response Playbook
Technique: T1547.001

## Detection Context
One of the oldest and still most common persistence techniques: adding an entry to
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
`HKLM\Software\Microsoft\Windows\CurrentVersion\Run` (or the `RunOnce` variants), or
dropping a shortcut into the user's Startup folder, so a payload executes automatically at
logon. In Sysmon, this appears as Event ID 13 (registry value set) targeting one of the Run
key paths, or Event ID 11 (file creation) in
`...\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`. Suspicious indicators:
value data pointing to scripts/executables in `%TEMP%`, `%APPDATA%`, or `C:\Users\Public\`;
value names mimicking legitimate software; the registry write immediately following a
suspicious download or PowerShell execution event.

## Investigation Steps
1. Pull the full registry value (`Details` field in Event ID 13) and identify the exact
   command/path it will execute at next logon.
2. Identify the process that made the registry write and its parent chain — a browser or
   Office app writing directly to a Run key is highly anomalous.
3. Check whether the referenced binary/script still exists on disk and inspect it if so.
4. Check for the same or similarly-named Run key entries on other hosts (mass deployment
   indicator).
5. Correlate timing with any recent phishing email, download, or exploit activity on the
   host.

## Containment
- Remove the malicious registry value (`reg delete` on the specific value, not the whole key).
- Delete/quarantine the referenced payload file.
- Isolate the host if the payload is confirmed to still be active in memory.

## Remediation
- Force a logoff/reboot after cleanup to ensure no lingering process from the persisted
  payload survives.
- Review the user's other autorun locations (Startup folder, Winlogon Shell/Userinit,
  services) for related entries left by the same actor.
- Reset credentials for the affected account if initial access involved credential theft.
