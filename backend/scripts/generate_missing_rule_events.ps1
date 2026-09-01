<#
.SYNOPSIS
  Generates real Sysmon events for the 3 NightOwl detection rules that
  never fire anywhere in the existing sample_logs/sysmon_malicious_demo.evtx
  capture: Registry Run Key Persistence (T1547.001), Registry IFEO Debugger
  Hijack (T1546.012), and Certutil Download via urlcache/split (T1105).

.DESCRIPTION
  Diagnosed by re-running the real detection engine over every one of the
  7,568 records in sysmon_malicious_demo.evtx: it contains zero Sysmon
  EventID 13 (RegistryEvent) records at all -- registry monitoring was not
  enabled in that capture's Sysmon config -- and its certutil.exe process-
  creation event never got logged (2 certutil-related FileCreate records
  exist, but no ProcessCreate record; the leading theory is real-time AV
  intercepted certutil.exe -urlcache -split before Sysmon could log it,
  since that exact flag combination is a well-known LOLBin signature).

  This is NOT malware, same posture as vm_generate_malicious_demo_events.ps1:
    - the certutil step hits a real but harmless URL (google.com/robots.txt)
    - every registry key this script creates is removed again immediately
    - the IFEO key targets a made-up executable name nothing ever invokes
    - nothing is installed, no scheduled task, no persistence left behind

.SAFETY
  Run in an ELEVATED PowerShell window (Run as Administrator) -- both
  writing HKLM (the IFEO step) and reading/exporting the Sysmon Operational
  log require admin rights; a non-elevated shell gets
  "UnauthorizedAccessException" on both.

  Unlike vm_generate_malicious_demo_events.ps1, this is written to run on
  your own host machine (by your own choice), not a disposable VM -- it
  only performs the 3 narrow, self-cleaning actions above, nothing else.

  The wevtutil export window is the ~4 seconds around these 3 commands
  only, not the whole log. Sysmon logs system-wide, so that narrow window
  may also contain a small amount of ordinary background activity from
  this machine at that moment (another process starting, a routine network
  connection) -- same as any real Sysmon capture, nothing this script
  controls.

.USAGE
  1. Open PowerShell as Administrator.
  2. cd to backend/scripts and run: .\generate_missing_rule_events.ps1
  3. It writes backend/sample_logs/missing_rules_registry_certutil.evtx.
     Hand that file back so it can be folded into the demo fixture set.
#>

$ErrorActionPreference = 'Continue'

$outPath = Join-Path $PSScriptRoot '..\sample_logs\missing_rules_registry_certutil.evtx'
$startTime = (Get-Date).ToUniversalTime().AddSeconds(-1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
Write-Host "=== NightOwl missing-rule event generation starting: $startTime ==="

# 1. Registry Run Key Persistence (T1547.001) -- HKCU, no elevation needed
#    for this step alone, but the script as a whole still requires it.
Write-Host "[1/3] registry run key persistence"
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Set-ItemProperty -Path $runKey -Name 'NightOwlTest' -Value 'C:\Users\Public\nightowl_update_test.exe' -Force
Remove-ItemProperty -Path $runKey -Name 'NightOwlTest' -Force -ErrorAction SilentlyContinue

# 2. Registry IFEO Debugger Hijack (T1546.012) -- HKLM, fake target name,
#    nothing on the system ever invokes it.
Write-Host "[2/3] registry ifeo debugger hijack (safe fake target)"
$ifeoKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\NightOwlTestTarget.exe'
New-Item -Path $ifeoKey -Force | Out-Null
Set-ItemProperty -Path $ifeoKey -Name 'Debugger' -Value 'C:\Windows\System32\cmd.exe' -Force
Remove-Item -Path $ifeoKey -Force -Recurse -ErrorAction SilentlyContinue

# 3. Certutil Download via urlcache/split (T1105) -- real but harmless URL.
#    May still get blocked/intercepted by AV, same as it apparently was on
#    the original capture VM -- if so this one rule stays uncovered and
#    that's fine, the other two are the main goal.
Write-Host "[3/3] certutil urlcache/split (real but harmless URL; AV may still block this)"
$certOut = "$env:TEMP\nightowl_test_download.txt"
certutil.exe -urlcache -split -f "https://www.google.com/robots.txt" $certOut 2>$null | Out-Null
Remove-Item -Path $certOut -Force -ErrorAction SilentlyContinue

Start-Sleep -Seconds 2
$endTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
Write-Host "=== Done. Window for export: $startTime  to  $endTime ==="

$query = "*[System[TimeCreated[@SystemTime>='$startTime'] and TimeCreated[@SystemTime<='$endTime']]]"
wevtutil epl "Microsoft-Windows-Sysmon/Operational" $outPath /q:$query /ow:true

if (Test-Path $outPath) {
    Write-Host "`nWrote $outPath"
    Write-Host "Hand this file back so it can be folded into the demo fixture set."
} else {
    Write-Host "`nExport did not produce a file -- check the wevtutil error above (likely needs elevation)."
}
