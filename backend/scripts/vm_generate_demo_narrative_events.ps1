<#
.SYNOPSIS
  Generates a realistic, narratively-coherent Sysmon capture for the live judge
  demo -- a single 5-stage attack kill chain, interleaved with ordinary benign
  activity, spread over several minutes instead of the rule-coverage fixture's
  15-actions-in-29-seconds burst.

.DESCRIPTION
  This is a DIFFERENT fixture than sysmon_malicious_demo.evtx (which stays as
  the Phase 4 / E2E rule-coverage file -- 12/15 rules, see
  docs/05_NightOwl_Manual_Testing_Guide.md §12.7). This one is deliberately
  narrower and paced like a real intrusion, for presenting to a judging panel:

    t+0s    [benign]     whoami                          -- normal session start
    t+20s   [benign]     cmd.exe /c dir Documents         -- normal file browsing
    t+45s   [MALICIOUS]  T1059.001  Encoded PowerShell    -- initial execution
    t+110s  [benign]     notepad.exe opens briefly        -- normal user activity
    t+140s  [MALICIOUS]  T1105      Suspicious file write -- tool staging
    t+200s  [benign]     ping.exe 127.0.0.1               -- normal connectivity check
    t+230s  [MALICIOUS]  T1053.005  Scheduled task        -- persistence
    t+300s  [benign]     schtasks /query                  -- normal task query
    t+330s  [MALICIOUS]  T1003.001  LSASS dump signature  -- credential access
    t+400s  [benign]     tasklist.exe                     -- normal admin activity
    t+430s  [MALICIOUS]  T1021.001  RDP (loopback)         -- lateral movement
    t+460s  [benign]     ipconfig /all                    -- normal networking check

  ~8 minutes total. 5 malicious actions across 4 tactics (Execution, C2-staging
  via T1105, Persistence, Credential Access, Lateral Movement), 6 benign actions
  that do NOT match any of the 15 rules (verified against their exact
  Image/CommandLine/TargetFilename conditions in backend/detection/rules/*.yml)
  so they show up as ordinary noise, not extra alerts. Every benign step is
  deliberately an external process (cmd.exe, ping.exe, tasklist.exe, ...) rather
  than a plain PowerShell cmdlet (Get-ChildItem, Test-Connection, Get-Process) --
  a cmdlet running inside this already-open PowerShell session spawns no new
  process and so would never appear as a Sysmon ProcessCreate event at all,
  which would defeat the point of showing it as visible background noise.

  Same non-destructive safety principles as vm_generate_malicious_demo_events.ps1:
  no real payload downloaded/executed, no real credential/memory access, every
  artifact this script creates is removed before it exits, network rule uses
  127.0.0.1 only.

.SAFETY
  Run this ONLY on the disposable/snapshot Sysmon-enabled VM. Run as
  Administrator (schtasks /create needs it in some configs).

.USAGE
  1. Run this script on the VM (elevated PowerShell). Takes ~8 minutes.
  2. It prints a start/end UTC timestamp window and the wevtutil export
     command with those timestamps filled in.
  3. Copy the resulting file into this repo as
     data/sample_logs/sysmon_demo_narrative.evtx
#>

$ErrorActionPreference = 'Continue'
$startTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
Write-Host "=== NightOwl demo-narrative event generation starting: $startTime ==="
Write-Host "(this takes about 8 minutes -- steps are deliberately spaced out)"

function Invoke-LoopbackConnection {
    param([int]$Port)
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
    $listener.Start()
    try {
        $acceptTask = $listener.AcceptTcpClientAsync()
        $client = [System.Net.Sockets.TcpClient]::new()
        $client.Connect('127.0.0.1', $Port)
        $acceptTask.Wait(2000) | Out-Null
        Start-Sleep -Milliseconds 300
        $client.Close()
    } finally {
        $listener.Stop()
    }
}

# --- t+0s [benign] normal session start ---
Write-Host "[1/11] (benign) whoami"
whoami | Out-Null

Start-Sleep -Seconds 20

# --- t+20s [benign] normal file browsing ---
Write-Host "[2/11] (benign) browse Documents"
cmd.exe /c "dir `"$env:USERPROFILE\Documents`"" 2>$null | Out-Null

Start-Sleep -Seconds 25

# --- t+45s [MALICIOUS] T1059.001 initial execution ---
Write-Host "[3/11] (MALICIOUS) encoded powershell -- initial execution"
powershell.exe -EncodedCommand aQBlAHgA 2>$null

Start-Sleep -Seconds 65

# --- t+110s [benign] normal user activity ---
Write-Host "[4/11] (benign) notepad opens briefly"
$notepad = Start-Process notepad.exe -PassThru
Start-Sleep -Seconds 2
Stop-Process -Id $notepad.Id -Force -ErrorAction SilentlyContinue

Start-Sleep -Seconds 28

# --- t+140s [MALICIOUS] T1105 tool staging ---
Write-Host "[5/11] (MALICIOUS) suspicious file write -- tool staging"
$dropPath = "C:\Users\Public\nightowl_update_test.exe"
New-Item -Path $dropPath -ItemType File -Force | Out-Null
Remove-Item -Path $dropPath -Force -ErrorAction SilentlyContinue

Start-Sleep -Seconds 58

# --- t+200s [benign] normal connectivity check (ICMP, no Sysmon NetworkConnect event) ---
Write-Host "[6/11] (benign) ping check"
ping.exe -n 1 127.0.0.1 2>$null | Out-Null

Start-Sleep -Seconds 28

# --- t+230s [MALICIOUS] T1053.005 persistence ---
Write-Host "[7/11] (MALICIOUS) schtasks /create -- persistence"
schtasks.exe /create /tn "NightOwlTestTask" /tr "cmd.exe /c exit" /sc onlogon /f 2>$null | Out-Null
schtasks.exe /delete /tn "NightOwlTestTask" /f 2>$null | Out-Null

Start-Sleep -Seconds 68

# --- t+300s [benign] normal task query (does NOT match the /create rule) ---
Write-Host "[8/11] (benign) schtasks /query"
schtasks.exe /query /fo LIST 2>$null | Out-Null

Start-Sleep -Seconds 28

# --- t+330s [MALICIOUS] T1003.001 credential access (echo signature only, no real dump) ---
Write-Host "[9/11] (MALICIOUS) comsvcs.dll MiniDump signature -- credential access"
cmd.exe /c "echo comsvcs.dll MiniDump nightowl-test>nul"

Start-Sleep -Seconds 68

# --- t+400s [benign] normal admin activity ---
Write-Host "[10/11] (benign) tasklist"
tasklist.exe 2>$null | Out-Null

Start-Sleep -Seconds 28

# --- t+430s [MALICIOUS] T1021.001 lateral movement (loopback only) ---
Write-Host "[11a/11] (MALICIOUS) rdp-port loopback connection -- lateral movement"
Invoke-LoopbackConnection -Port 3389

Start-Sleep -Seconds 28

# --- t+460s [benign] normal networking check ---
Write-Host "[11b/11] (benign) ipconfig /all"
ipconfig /all | Out-Null

$endTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
Write-Host ""
Write-Host "=== Done. Window for export: $startTime  to  $endTime ==="
Write-Host 'wevtutil epl Microsoft-Windows-Sysmon/Operational C:\path\sysmon_demo_narrative.evtx /q:"*[System[TimeCreated[@SystemTime>=''' + $startTime + '''] and TimeCreated[@SystemTime<=''' + $endTime + ''']]]"'
