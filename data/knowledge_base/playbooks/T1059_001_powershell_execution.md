# Suspicious PowerShell Execution Response Playbook
Technique: T1059.001

## Detection Context
Attackers frequently use PowerShell for execution because it is installed by default on
Windows, runs .NET code directly in memory, and can be heavily obfuscated. Common signals
in Sysmon Event ID 1 (process creation) include: `-EncodedCommand`/`-enc` flags, `-NoProfile
-NonInteractive -WindowStyle Hidden` combinations, `IEX (New-Object Net.WebClient).DownloadString(...)`
download-cradle patterns, and unusually long or base64-heavy command lines. PowerShell spawned
as a child of Office applications (WINWORD.EXE, EXCEL.EXE) or a script host is a strong
indicator of malicious macro or phishing-driven execution.

## Investigation Steps
1. Decode any base64/encoded command block and read the underlying script before doing
   anything else — do not run it, just read it.
2. Identify the parent process (Event ID 1 `ParentImage`). PowerShell spawned by
   `outlook.exe`, `winword.exe`, `excel.exe`, or a browser strongly suggests phishing/drive-by
   delivery rather than legitimate admin activity.
3. Check the full command line for download cradles (`DownloadString`, `Invoke-WebRequest`,
   `IEX`, `Net.WebClient`) and note any URLs or IPs contacted — these become indicators to
   block and pivot on across other hosts.
4. Review the logged-on user and whether this activity fits their normal role (e.g. a
   front-desk account running an encoded PowerShell one-liner at 2am is anomalous).
5. Check for related persistence artifacts created by the same process tree (scheduled
   tasks, registry Run keys, new services) in the minutes following execution.

## Containment
- Isolate the host from the network if the decoded script shows C2/download behavior.
- Kill the PowerShell process tree and any spawned child processes.
- Block identified C2 domains/IPs at the perimeter/DNS layer.

## Remediation
- Reset credentials for the affected user if credential theft is suspected.
- Remove any persistence mechanisms created by the malicious script.
- Consider enabling PowerShell Script Block Logging (Event ID 4104) and Constrained
  Language Mode to reduce blast radius of future encoded/obfuscated execution.
